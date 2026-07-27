<?php

/*
 * This file is part of the 2amigos/yii2-usuario project.
 *
 * (c) 2amigOS! <http://2amigos.us/>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace Da\User\Model;

use Da\User\Query\AuthTfRecoveryCodeQuery;
use Da\User\Traits\ContainerAwareTrait;
use Da\User\Traits\ModuleAwareTrait;
use yii\db\ActiveRecord;

/**
 * A single-use two-factor-authentication recovery code.
 *
 * Only the {@see \Yii::$app->security::generatePasswordHash() hash} of the code is
 * persisted (`code_hash`) — the plaintext code is only ever known to the caller that
 * generated it, for the one response where it is shown to the user.
 *
 * @property int    $id
 * @property int    $user_id
 * @property string $code_hash
 * @property int    $used_at
 * @property int    $created_at
 * @property bool   $isUsed
 * @property User   $user
 */
class AuthTfRecoveryCode extends ActiveRecord
{
    use ModuleAwareTrait;
    use ContainerAwareTrait;

    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return '{{%auth_tf_recovery_code}}';
    }

    /**
     * {@inheritdoc}
     */
    public function beforeSave($insert)
    {
        if ($insert) {
            $this->setAttribute('created_at', time());
        }

        return parent::beforeSave($insert);
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getUser()
    {
        return $this->hasOne($this->getClassMap()->get(User::class), ['id' => 'user_id']);
    }

    /**
     * @return bool
     */
    public function getIsUsed()
    {
        return $this->used_at !== null;
    }

    /**
     * Marks the code as consumed, so it cannot be used again.
     *
     * @return bool
     */
    public function markUsed()
    {
        return $this->updateAttributes(['used_at' => time()]);
    }

    /**
     * @return AuthTfRecoveryCodeQuery
     */
    public static function find()
    {
        return new AuthTfRecoveryCodeQuery(static::class);
    }
}
