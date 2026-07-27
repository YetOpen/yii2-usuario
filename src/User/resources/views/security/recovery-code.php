<?php

/*
 * This file is part of the 2amigos/yii2-usuario project.
 *
 * (c) 2amigOS! <http://2amigos.us/>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

use yii\helpers\Html;

/**
 * @var yii\web\View    $this
 * @var \Da\User\Module $module
 */

$this->title = Yii::t('usuario', 'Recovery code');
$this->params['breadcrumbs'][] = $this->title;
?>

<?= $this->render('/shared/_alert', ['module' => Yii::$app->getModule('user')]) ?>

<div class="row">
    <div class="col-md-4 col-md-offset-4 col-sm-6 col-sm-offset-3">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title"><?= Html::encode($this->title) ?></h3>
            </div>
            <div class="panel-body">
                <p>
                    <?= Yii::t(
                        'usuario',
                        'Enter one of the recovery codes you saved when you enabled two factor authentication. This will disable two factor authentication on your account.'
                    ) ?>
                </p>
                <?= Html::beginForm('', 'post', ['id' => 'recovery-code-form']) ?>
                <div class="form-group">
                    <label for="recoveryCode"><?= Yii::t('usuario', 'Recovery code') ?></label>
                    <?= Html::textInput(
                        'recoveryCode',
                        null,
                        [
                            'id' => 'recoveryCode',
                            'class' => 'form-control',
                            'autofocus' => 'autofocus',
                            'tabindex' => '1',
                        ]
                    ) ?>
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <?= Html::a(
                            Yii::t('usuario', 'Back'),
                            ['confirm'],
                            ['class' => 'btn btn-default btn-block', 'tabindex' => '3']
                        ) ?>
                    </div>
                    <div class="col-md-6">
                        <?= Html::submitButton(
                            Yii::t('usuario', 'Disable and continue'),
                            ['class' => 'btn btn-primary btn-block', 'tabindex' => '2']
                        ) ?>
                    </div>
                </div>
                <?= Html::endForm() ?>
            </div>
        </div>
    </div>
</div>
