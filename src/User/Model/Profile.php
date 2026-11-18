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

use Da\User\Helper\GravatarHelper;
use Da\User\Query\ProfileQuery;
use Da\User\Traits\ContainerAwareTrait;
use Da\User\Traits\ModuleAwareTrait;
use Da\User\Validator\TimeZoneValidator;
use DateTime;
use DateTimeZone;
use Exception;
use Yii;
use yii\base\InvalidConfigException;
use yii\base\InvalidParamException;
use yii\db\ActiveRecord;
use yii\web\UploadedFile;

/**
 * @property int    $user_id
 * @property string $name
 * @property string $public_email
 * @property string $gravatar_email
 * @property string $gravatar_id
 * @property string $location
 * @property string $website
 * @property string $bio
 * @property string $image
 * @property string $timezone
 * @property string|null $phone the user's mobile number, international format (`+393401234567`)
 * @property User   $user
 */
class Profile extends ActiveRecord
{
    use ModuleAwareTrait;
    use ContainerAwareTrait;

    /**
     * The administrator's edit of a profile (`AdminController::actionUpdateProfile()`): the only
     * place `phone` can be set. An application may identify a user by that number (e.g. a
     * messaging integration acting as whoever writes from it), so users must not set it on
     * themselves — in the default scenario it is not even mass-assignable.
     */
    public const SCENARIO_ADMIN = 'admin';

    /** `+`, a country code and the number: 8 to 15 digits in all (E.164). */
    public const PHONE_PATTERN = '/^\+[1-9]\d{7,14}$/';

    /**
     * @var UploadedFile
     */
    public $imageUpload;

    /**
     * {@inheritDoc}
     */
    public function beforeValidate()
    {
        $this->imageUpload = UploadedFile::getInstance($this, 'imageUpload');
        return parent::beforeValidate();
    }

    /**
     * {@inheritdoc}
     *
     * @throws InvalidParamException
     * @throws InvalidConfigException
     */
    public function beforeSave($insert)
    {
        if ($this->isAttributeChanged('gravatar_email')) {
            $this->setAttribute(
                'gravatar_id',
                $this->make(GravatarHelper::class)->buildId(trim($this->getAttribute('gravatar_email')))
            );
        }

        if ($this->imageUpload instanceof UploadedFile) {
            $this->image = file_get_contents($this->imageUpload->tempName);
        }

        return parent::beforeSave($insert);
    }

    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return '{{%profile}}';
    }

    /**
     * {@inheritdoc}
     *
     * @throws InvalidConfigException
     */
    public function rules()
    {
        return [
            'bioString' => ['bio', 'string'],
            'timeZoneValidation' => [
                'timezone',
                function ($attribute) {
                    if ($this->make(TimeZoneValidator::class, [$this->{$attribute}])->validate() === false) {
                        $this->addError($attribute, Yii::t('usuario', 'Time zone is not valid'));
                    }
                },
            ],
            'publicEmailPattern' => ['public_email', 'email'],
            'gravatarEmailPattern' => ['gravatar_email', 'email'],
            'websiteUrl' => ['website', 'url'],
            'nameLength' => ['name', 'string', 'max' => 255],
            'publicEmailLength' => ['public_email', 'string', 'max' => 255],
            'gravatarEmailLength' => ['gravatar_email', 'string', 'max' => 255],
            'locationLength' => ['location', 'string', 'max' => 255],
            'websiteLength' => ['website', 'string', 'max' => 255],
            'imageSafe' => ['image', 'safe'],
            'phoneNormalize' => ['phone', 'filter', 'filter' => [static::class, 'normalizePhone'], 'on' => self::SCENARIO_ADMIN],
            'phoneEmpty' => ['phone', 'default', 'value' => null, 'on' => self::SCENARIO_ADMIN],
            'phonePattern' => ['phone', 'match', 'pattern' => self::PHONE_PATTERN, 'on' => self::SCENARIO_ADMIN,
                'message' => Yii::t('usuario', 'The phone number must be in international format, e.g. +393401234567.')],
            'imageFile' => [
                'imageUpload', 'file',
                'skipOnEmpty' => true,
                'extensions' => ['png', 'jpg', 'jpeg'],
                'checkExtensionByMimeType' => false,
                'maxSize' => $this->module->maxProfileImageSize,
            ],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'name' => Yii::t('usuario', 'Name'),
            'public_email' => Yii::t('usuario', 'Email (public)'),
            'gravatar_email' => Yii::t('usuario', 'Gravatar email'),
            'location' => Yii::t('usuario', 'Location'),
            'website' => Yii::t('usuario', 'Website'),
            'bio' => Yii::t('usuario', 'Bio'),
            'timezone' => Yii::t('usuario', 'Time zone'),
            'phone' => Yii::t('usuario', 'Mobile phone'),
            'image' => Yii::t('usuario', 'Image'),
            'imageUpload' => Yii::t('usuario', 'Profile Image'),
        ];
    }

    /**
     * Get the User's timezone.
     *
     * @return DateTimeZone
     */
    public function getTimeZone()
    {
        try {
            return new DateTimeZone($this->timezone);
        } catch (Exception $e) {
            return new DateTimeZone(Yii::$app->getTimeZone());
        }
    }

    /**
     * Set the User's timezone.
     *
     * @param DateTimeZone $timezone
     *
     * @throws InvalidParamException
     */
    public function setTimeZone(DateTimeZone $timezone)
    {
        $this->setAttribute('timezone', $timezone->getName());
    }

    /**
     * Get User's local time.
     *
     * @param DateTime|null $dateTime
     *
     * @return DateTime
     */
    public function getLocalTimeZone(?DateTime $dateTime = null)
    {
        return $dateTime === null ? new DateTime() : $dateTime->setTimezone($this->getTimeZone());
    }

    /**
     * @throws InvalidConfigException
     * @return \yii\db\ActiveQuery
     */
    public function getUser()
    {
        return $this->hasOne($this->getClassMap()->get(User::class), ['id' => 'user_id']);
    }

    /**
     * @param int $size
     *
     * @throws InvalidConfigException
     * @return mixed
     */
    public function getAvatarUrl($size = 200)
    {
        return $this->make(GravatarHelper::class)->getUrl($this->gravatar_id, $size);
    }

    /**
     * @return string|null
     */
    public function getImageUrl(): ?string
    {
        if ($this->image) {
            return 'data:image/*;base64,' . base64_encode($this->image);
        }
        return null;
    }


    /**
     * @return ProfileQuery
     */
    public static function find()
    {
        return new ProfileQuery(static::class);
    }

    /**
     * The number without spaces, dots, dashes or brackets; an empty value stays empty.
     *
     * @param mixed $phone
     */
    public static function normalizePhone($phone): ?string
    {
        $phone = preg_replace('/[\s.\-()]/', '', (string)$phone);

        return $phone === '' ? null : $phone;
    }
}
