<?php

/*
 * This file is part of the 2amigos/yii2-usuario project.
 *
 * (c) 2amigOS! <http://2amigos.us/>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace Da\User\Form;

use Da\User\Factory\EmailChangeStrategyFactory;
use Da\User\Helper\SecurityHelper;
use Da\User\Model\User;
use Da\User\Traits\ContainerAwareTrait;
use Da\User\Traits\ModuleAwareTrait;
use Yii;
use yii\base\InvalidConfigException;
use yii\base\InvalidParamException;
use yii\base\Model;
use yii\base\ModelEvent;
use yii\helpers\ArrayHelper;

class SettingsForm extends Model
{
    use ModuleAwareTrait;
    use ContainerAwareTrait;

    /**
     * Triggered (once per form) to ask whether the user may set a new password from this form.
     * The handler receives a {@see ModelEvent} whose `sender` is this form, so it can read the user through
     * {@see getUser()}, and sets `isValid` to `false` to refuse the change. Without handlers the change is allowed.
     */
    const EVENT_PASSWORD_CHANGE_ALLOWED = 'passwordChangeAllowed';

    /**
     * @var string
     */
    public $email;
    /**
     * @var string
     */
    public $username;
    /**
     * @var string
     */
    public $new_password;
    /**
     * @var string
     */
    public $current_password;
    /**
     * @var SecurityHelper
     */
    protected $securityHelper;

    /** @var User */
    protected $user;

    /**
     * @var bool|null memoised answer of {@see isPasswordChangeAllowed()}
     */
    private $passwordChangeAllowed;

    /**
     * SettingsForm constructor.
     *
     * @param SecurityHelper $securityHelper
     * @param array          $config
     */
    public function __construct(SecurityHelper $securityHelper, array $config = [])
    {
        $this->securityHelper = $securityHelper;
        $config = ArrayHelper::merge(
            [
                'username' => $this->getUser()->username,
                'email' => $this->getUser()->unconfirmed_email ?: $this->getUser()->email
            ],
            $config
        );
        parent::__construct($config);
    }

    /**
     * @throws InvalidConfigException
     * @throws InvalidParamException
     * @return array
     *
     */
    public function rules()
    {
        return [
            'usernameRequired' => ['username', 'required'],
            'usernameTrim' => ['username', 'filter', 'filter' => 'trim'],
            'usernameLength' => ['username', 'string', 'min' => 3, 'max' => 255],
            'usernamePattern' => ['username', 'match', 'pattern' => '/^[-a-zA-Z0-9_\.@]+$/'],
            'emailRequired' => ['email', 'required'],
            'emailTrim' => ['email', 'filter', 'filter' => 'trim'],
            'emailPattern' => ['email', 'email'],
            'emailUsernameUnique' => [
                ['email', 'username'],
                'unique',
                'when' => function ($model, $attribute) {
                    return $this->getUser()->$attribute !== $model->$attribute;
                },
                'targetClass' => $this->getClassMap()->get(User::class),
            ],
            'newPasswordLength' => ['new_password', 'string', 'max' => 72, 'min' => 6],
            'newPasswordAllowed' => [
                'new_password',
                function ($attribute) {
                    if (!$this->isPasswordChangeAllowed()) {
                        $this->addError(
                            $attribute,
                            Yii::t('usuario', 'Your password is managed by your organisation\'s directory and cannot be changed here.')
                        );
                    }
                },
            ],
            'currentPasswordRequired' => ['current_password', 'required'],
            'currentPasswordValidate' => [
                'current_password',
                function ($attribute) {
                    if (!$this->securityHelper->validatePassword($this->$attribute, $this->getUser()->password_hash)) {
                        $this->addError($attribute, Yii::t('usuario', 'Current password is not valid'));
                    }
                },
            ],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'email' => Yii::t('usuario', 'Email'),
            'username' => Yii::t('usuario', 'Username'),
            'new_password' => Yii::t('usuario', 'New password'),
            'current_password' => Yii::t('usuario', 'Current password'),
        ];
    }

    /**
     * @return User|null|\yii\web\IdentityInterface
     */
    public function getUser()
    {
        if (null === $this->user) {
            $this->user = Yii::$app->user->identity;
        }

        return $this->user;
    }

    /**
     * Whether the user may set a new password from this form, as answered by the handlers of
     * {@see EVENT_PASSWORD_CHANGE_ALLOWED}. Allowed when nobody objects.
     *
     * @return bool
     */
    public function isPasswordChangeAllowed()
    {
        if ($this->passwordChangeAllowed === null) {
            /** @var ModelEvent $event */
            $event = $this->make(ModelEvent::class);
            $this->trigger(self::EVENT_PASSWORD_CHANGE_ALLOWED, $event);
            $this->passwordChangeAllowed = (bool)$event->isValid;
        }

        return $this->passwordChangeAllowed;
    }

    /**
     * Saves new account settings.
     *
     * @throws \Exception
     * @return bool
     *
     */
    public function save()
    {
        if ($this->validate()) {
            $user = $this->getUser();
            if ($user instanceof User) {
                $user->scenario = 'settings';
                $user->username = $this->username;
                $user->password = $this->new_password;
                if ($this->email === $user->email && $user->unconfirmed_email !== null) {
                    $user->unconfirmed_email = null;
                } elseif ($this->email !== $user->email) {
                    $strategy = EmailChangeStrategyFactory::makeByStrategyType(
                        $this->getModule()->emailChangeStrategy,
                        $this
                    );

                    return $strategy->run();
                }

                return $user->save();
            }
        }

        return false;
    }
}
