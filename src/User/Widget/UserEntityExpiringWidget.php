<?php

namespace Da\User\Widget;

use Da\User\Model\User;
use Da\User\Model\UserEntity;
use Da\User\Traits\ModuleAwareTrait;
use Yii;
use yii\base\Widget;

class UserEntityExpiringWidget extends Widget
{
    use ModuleAwareTrait;

    public function run()
    {
        $module = $this->getModule();
        /** @var User|null $user */
        $user = Yii::$app->user->identity;
        if ($user === null || !$module->enablePasskeyExpiringNotification) {
            return '';
        }

        $expiringPasskeys = $user->getUserEntities()->expiring()->all();
        if (empty($expiringPasskeys)) {
            return '';
        }

        $popupData = $this->buildPopupData($expiringPasskeys);

        return $this->render('user-entity/pop-up-expiration', [
            'popupData' => $popupData,
            'count' => count($popupData),
        ]);
    }

    /**
     * @param UserEntity[] $expiringPasskeys
     * @return array<int, array{id:int, name:string, daysLeft:int, expirationDate:string}>
     */
    private function buildPopupData(array $expiringPasskeys): array
    {
        $popupData = [];
        $maxAgeDays = (int) $this->getModule()->maxPasskeyAge;
        $now = new \DateTimeImmutable();

        foreach ($expiringPasskeys as $passkey) {
            $lastActivity = (int) ($passkey->last_used_at ?: $passkey->created_at ?: time());
            $expirationDate = (new \DateTimeImmutable())
                ->setTimestamp($lastActivity)
                ->modify("+{$maxAgeDays} days");
            $daysLeft = (int) $now->diff($expirationDate)->format('%r%a');

            $popupData[] = [
                'id' => (int) $passkey->id,
                'name' => $passkey->name ?? '-',
                'daysLeft' => max(0, $daysLeft),
                'expirationDate' => $expirationDate->format('Y-m-d'),
            ];
        }

        return $popupData;
    }
}
