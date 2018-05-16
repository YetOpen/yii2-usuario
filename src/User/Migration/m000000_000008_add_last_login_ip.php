<?php
namespace Da\User\Migration;

use yii\db\Migration;
use yii\db\Schema;


/**
 * Class m000000_000008_add_last_login_ip
 * @author: Kartik Visweswaran
 */
class m000000_000008_add_last_login_ip extends Migration
{
    /**
     * {@inheritdoc}
     */
    public function safeUp()
    {
        $this->addColumn('{{%user}}', 'last_login_ip', Schema::TYPE_STRING . '(45) DEFAULT NULL AFTER last_login_at');
    }

    /**
     * {@inheritdoc}
     */
    public function safeDown()
    {
        $this->dropColumn('{{%user}}', 'last_login_ip');
    }
}
