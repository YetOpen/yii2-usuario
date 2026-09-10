<?php

namespace Da\User\Model;

use Da\User\Query\UserEntityQuery;
use Yii;
use yii\db\ActiveRecord;

/**
 * This is the model class for table "user_entity" (passkey credentials).
 *
 * @property int         $id
 * @property int         $user_id
 * @property string      $credential_id   base64url-encoded credential id
 * @property string      $public_key      base64url-encoded COSE public key
 * @property int         $sign_count
 * @property string      $type            always "public-key"
 * @property string      $attestation_type  WebAuthn attestation type: none|basic|self|attca|anonca
 * @property string|null $device_id       user-agent hint captured at registration time
 * @property int         $created_at      UNIX timestamp
 * @property int|null    $last_used_at    UNIX timestamp
 * @property string|null $name
 * @property User        $r_user
 */
class UserEntity extends ActiveRecord
{
    /**
     * Transient, not persisted: carries the base64url-encoded clientDataJSON from the browser
     * to the controller during the registration ceremony, so it can be verified server-side.
     */
    public $client_data_json;

    public static function tableName()
    {
        return '{{%user_entity}}';
    }

    public function rules()
    {
        return [
            [['sign_count'], 'default', 'value' => 0],
            [['created_at'], 'default', 'value' => fn() => time()],
            ['attestation_type', 'default', 'value' => 'none'],
            [['user_id', 'credential_id', 'public_key', 'sign_count', 'type', 'attestation_type', 'name'], 'required'],
            [['user_id', 'sign_count', 'created_at', 'last_used_at'], 'integer'],
            [['public_key'], 'string'],
            [['credential_id'], 'string', 'max' => 512],
            [['credential_id'], 'unique'],
            [['type'], 'string', 'max' => 32],
            [['attestation_type'], 'string', 'max' => 32],
            [['device_id'], 'string', 'max' => 512],
            [['name'], 'string', 'min' => 4, 'max' => 128],
            ['name', 'match', 'pattern' => '/^[a-zA-Z0-9 ]+$/', 'message' => Yii::t('usuario', 'The name can contain only letters, numbers, and spaces.')],
            ['attestation_type', 'in', 'range' => ['none', 'basic', 'self', 'attca', 'anonca'],
                'message' => Yii::t('usuario', 'Your attestation type is invalid and isn\'t supported.')],
        ];
    }

    public function attributeLabels()
    {
        return [
            'id' => Yii::t('usuario', 'ID'),
            'user_id' => Yii::t('usuario', 'User ID'),
            'credential_id' => Yii::t('usuario', 'Credential ID'),
            'public_key' => Yii::t('usuario', 'Public Key'),
            'sign_count' => Yii::t('usuario', 'Sign Count'),
            'type' => Yii::t('usuario', 'Type'),
            'attestation_type' => Yii::t('usuario', 'Attestation Type'),
            'device_id' => Yii::t('usuario', 'Device ID'),
            'created_at' => Yii::t('usuario', 'Created At'),
            'last_used_at' => Yii::t('usuario', 'Last Used At'),
            'name' => Yii::t('usuario', 'Name'),
        ];
    }

    /**
     * @return UserEntityQuery
     */
    public static function find()
    {
        return new UserEntityQuery(static::class);
    }
}
