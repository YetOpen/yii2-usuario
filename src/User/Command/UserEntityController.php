<?php

namespace Da\User\Command;

use Da\User\Model\UserEntity;
use Da\User\Traits\ModuleAwareTrait;
use yii\console\Controller;
use yii\db\Expression;

/**
 * Passkey maintenance commands.
 *
 * Register in a cron/scheduler, e.g. daily:
 *   php yii user/user-entity/delete-expired-passkeys
 *   php yii user/user-entity/delete-expired-passkeys --dryRun
 */
class UserEntityController extends Controller
{
    use ModuleAwareTrait;

    /**
     * @var bool when true, only report what would be deleted without touching the database.
     */
    public $dryRun = false;

    /**
     * {@inheritdoc}
     */
    public function options($actionID)
    {
        return array_merge(parent::options($actionID), ['dryRun']);
    }

    /**
     * Deletes passkeys that have not been used for `maxPasskeyAge` days. A passkey row holds the
     * only copy of its public key, so deletion is irreversible; the user's last remaining passkey
     * is never deleted, to avoid locking them out.
     *
     * The command operates on the stored credentials regardless of whether `enablePasskeyLogin` is
     * currently on: scheduling it is itself the opt-in, and with no expired passkeys it is a no-op.
     */
    public function actionDeleteExpiredPasskeys()
    {
        $module = $this->getModule();

        $maxDays = (int) $module->maxPasskeyAge;
        $cutoff = time() - $maxDays * 86400;
        $dateField = new Expression('COALESCE(last_used_at, created_at)');

        $expired = UserEntity::find()
            ->andWhere(['<=', $dateField, $cutoff])
            ->all();

        $deleted = 0;
        $skipped = 0;
        foreach ($expired as $passkey) {
            if (UserEntity::find()->where(['user_id' => $passkey->user_id])->count() <= 1) {
                $skipped++;
                continue;
            }
            if ($this->dryRun) {
                $this->stdout("[dry-run] would delete passkey #{$passkey->id} (user {$passkey->user_id})\n");
                $deleted++;
                continue;
            }
            if ($passkey->delete()) {
                $deleted++;
            }
        }

        $prefix = $this->dryRun ? '[dry-run] ' : '';
        $verb = $this->dryRun ? 'to delete' : 'deleted';
        $this->stdout("{$prefix}{$deleted} expired passkeys {$verb}, {$skipped} kept as last factor.\n");

        return self::EXIT_CODE_NORMAL;
    }
}
