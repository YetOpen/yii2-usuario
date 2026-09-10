<?php

use yii\bootstrap\BootstrapAsset;
use yii\grid\GridView;
use yii\helpers\Html;

/** @var yii\web\View $this */
/** @var yii\data\ActiveDataProvider $dataProvider */

// Glyphicons ship with the Bootstrap 3 assets usuario already depends on: no third-party CDN.
BootstrapAsset::register($this);

$this->registerCss(<<<CSS
.btn-no-style {
    background: none;
    border: none;
    padding: 0;
    margin: 0 5px;
    color: inherit;
    cursor: pointer;
    box-shadow: none;
    text-decoration: none;
}
CSS);
?>

<div class="table-responsive">
    <?= GridView::widget([
        'dataProvider' => $dataProvider,
        'summary' => false,
        'tableOptions' => ['class' => 'table table-bordered table-hover'],
        'columns' => [
            ['class' => 'yii\grid\SerialColumn'],

            'name',
            'device_id',
            'sign_count',
            [
                'attribute' => 'last_used_at',
                'value' => fn($model) => $model->last_used_at ? Yii::$app->formatter->asDatetime($model->last_used_at) : '-',
            ],
            [
                'attribute' => 'created_at',
                'value' => fn($model) => Yii::$app->formatter->asDatetime($model->created_at),
            ],
            [
                'label' => Yii::t('usuario', 'Expiration date'),
                'value' => function ($model) {
                    $module = Yii::$app->getModule('user');
                    $ts = (int) ($model->last_used_at ?: $model->created_at);
                    $expiration = (new \DateTimeImmutable())
                        ->setTimestamp($ts)
                        ->modify('+' . (int) $module->maxPasskeyAge . ' days');
                    return Yii::$app->formatter->asDate($expiration);
                },
            ],
            [
                'class' => 'yii\grid\ActionColumn',
                'header' => Yii::t('usuario', 'Actions'),
                'headerOptions' => ['style' => 'width:120px; text-align:center;'],
                'contentOptions' => ['style' => 'text-align:center;'],
                'template' => '{update} {delete}',
                'buttons' => [
                    'update' => fn($url, $model) =>
                    Html::a(
                        '<span class="glyphicon glyphicon-pencil"></span>',
                        ['user-entity/update-passkey', 'id' => $model->id],
                        [
                            'class' => 'btn-no-style',
                            'title' => Yii::t('usuario', 'Edit Passkey'),
                        ]
                    ),
                    'delete' => fn($url, $model) =>
                    Html::a(
                        '<span class="glyphicon glyphicon-trash"></span>',
                        ['user-entity/delete-passkey', 'id' => $model->id],
                        [
                            'class' => 'btn-no-style',
                            'title' => Yii::t('usuario', 'Delete Passkey'),
                            'data' => [
                                'confirm' => Yii::t('usuario', 'Are you sure you want to delete this passkey?'),
                                'method' => 'post',
                            ],
                        ]
                    ),
                ],
            ],
        ],
    ]); ?>
</div>
