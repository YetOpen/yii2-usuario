<?php

namespace Da\User\resources\assets;

use yii\web\AssetBundle;

class PasskeyAsset extends AssetBundle
{
    // Point at the js/ subdirectory only: with __DIR__ the bundle would publish PasskeyAsset.php
    // itself into the web-served assets directory.
    public $sourcePath = __DIR__ . '/js';

    public $js = [
        'passkey-login.js',
        'passkey-register.js',
    ];

    public $depends = [
        'yii\web\JqueryAsset',
    ];
}
