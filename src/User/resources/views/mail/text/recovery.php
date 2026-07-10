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
 * @var \Da\User\Model\Token $token
 * @var string|null          $resetUrl Frontend reset link; falls back to the backend web route.
 */
$link = !empty($resetUrl) ? $resetUrl : $token->url;
?>
<?= Yii::t('usuario', 'Hello') ?>,

<?= Yii::t('usuario', 'We have received a request to reset the password for your account on {0}', Yii::$app->name) ?>.
<?= Yii::t('usuario', 'Please click the link below to complete your password reset') ?>.

<?= $link ?>

<?= Yii::t('usuario', 'If you cannot click the link, please try pasting the text into your browser') ?>.

<?= Yii::t('usuario', 'If you did not make this request you can ignore this email') ?>.
