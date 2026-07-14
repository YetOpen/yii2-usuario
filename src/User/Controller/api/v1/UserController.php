<?php

namespace Da\User\Controller\api\v1;

use Da\User\Traits\ContainerAwareTrait;
use Da\User\Traits\ModuleAwareTrait;
use Da\User\Model\User;
use Yii;
use yii\filters\auth\CompositeAuth;
use yii\filters\Cors;
use yii\rest\Controller as RestController;

class UserController extends RestController
{
    use ContainerAwareTrait;
    use ModuleAwareTrait;

    /**
     * {@inheritdoc}
     */
    public function behaviors(): array
    {
        $behaviors = parent::behaviors();

        $behaviors['corsFilter'] = [
            'class' => Cors::class,
        ];

        $behaviors['authenticator'] = [
            'class' => CompositeAuth::class,
        ];

        return $behaviors;
    }

    /**
     * @return User
     */
    public function actionMe(): User
    {
        return Yii::$app->user->identity;
    }
}
