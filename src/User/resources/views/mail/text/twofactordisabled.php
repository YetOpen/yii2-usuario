<?php

/*
 * This file is part of the 2amigos/yii2-usuario project.
 *
 * (c) 2amigOS! <http://2amigos.us/>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

/**
 * @var \Da\User\Model\User $user
 */
?>
<?= Yii::t('usuario', 'Hello') ?>,

<?= Yii::t(
    'usuario',
    'Two factor authentication on your account on {0} has just been turned off using one of your recovery codes.',
    Yii::$app->name
) ?>

<?= Yii::t('usuario', 'If this was you, you can safely ignore this email. You may want to re-enable two factor authentication from your account settings.') ?>

<?= Yii::t('usuario', 'If this was not you, someone else may have access to your recovery codes. Please change your password and re-enable two factor authentication as soon as possible.') ?>
