<?php

use Da\User\Module;
use yii\helpers\Html;
use yii\widgets\ActiveForm;
use Da\User\resources\assets\PasskeyAsset;
use yii\helpers\Url;
use Da\User\Service\TranslationService;



/** @var yii\web\View $this */
/** @var Module         $module */
/** @var Da\User\Model\UserEntity $model */


$jsTranslations = TranslationService::translationPasskeyRegisterJs();

// translations for the passkey-register.js asset
?><script>window.PasskeyRegisterMessages = <?= json_encode($jsTranslations, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?>;</script>
<?php
$module = Yii::$app->getModule('user');
$this->title = Yii::t('usuario','Create a new passkey');


$this->registerJsVar('passkeyChallengeUrl', Url::to(['/user/user-entity/create-passkey-challenge']));

$count = \Da\User\Model\UserEntity::find()
    ->where(['user_id' => Yii::$app->user->id])
    ->count();

PasskeyAsset::register($this);
$this->registerJs(<<<JS
$('#passkey-form').bindPassKeyCreationSubmit();
JS);

?>

<h1><?= Html::encode($this->title) ?></h1>

<?php
if($count >= $module->maxPasskeysForUser){
    ?> <p><?= Yii::t('usuario', 'Sorry, you are allowed to have a maximum of {count} passkeys.', ['count' => $module->maxPasskeysForUser]) ?></p> <?php
}else{
?>
<div class="user-entity-form">

    <?php $form = ActiveForm::begin([
        'id' => 'passkey-form',
        'action' => ['/user/user-entity/store-passkey'],
        'method' => 'post',
    ]); ?>

    <?=$form->field($model, 'name')->textInput(['maxlength' => true])->label(Yii::t('usuario','Name for passkey')); ?>
    <?= Html::activeHiddenInput($model, 'credential_id', ['id' => 'credential_id']) ?>
    <?= Html::activeHiddenInput($model, 'public_key', ['id' => 'public_key']) ?>
    <?= Html::activeHiddenInput($model, 'client_data_json', ['id' => 'client_data_json']) ?>
    <div class="form-group">
        <?= Html::submitButton(Yii::t('usuario','Register Passkey'), ['class' => 'btn btn-success', 'id' => 'submit-button']) ?>
    </div>
    <?php ActiveForm::end();?>
</div>

<?php }
?>
