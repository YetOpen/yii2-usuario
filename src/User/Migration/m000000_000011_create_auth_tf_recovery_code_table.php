<?php

/*
 * This file is part of the 2amigos/yii2-usuario project.
 *
 * (c) 2amigOS! <http://2amigos.us/>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace Da\User\Migration;

use Da\User\Helper\MigrationHelper;
use yii\db\Migration;

class m000000_000011_create_auth_tf_recovery_code_table extends Migration
{
    public function safeUp()
    {
        $this->createTable(
            '{{%auth_tf_recovery_code}}',
            [
                'id' => $this->primaryKey(),
                'user_id' => $this->integer()->notNull(),
                'code_hash' => $this->string(255)->notNull(),
                'used_at' => $this->integer()->null(),
                'created_at' => $this->integer()->notNull(),
            ],
            MigrationHelper::resolveTableOptions($this->db->driverName)
        );

        $this->createIndex('idx_auth_tf_recovery_code_user_id', '{{%auth_tf_recovery_code}}', ['user_id']);

        $restrict = MigrationHelper::isMicrosoftSQLServer($this->db->driverName) ? 'NO ACTION' : 'RESTRICT';

        $this->addForeignKey(
            'fk_auth_tf_recovery_code_user',
            '{{%auth_tf_recovery_code}}',
            'user_id',
            '{{%user}}',
            'id',
            'CASCADE',
            $restrict
        );
    }

    public function safeDown()
    {
        $this->dropTable('{{%auth_tf_recovery_code}}');
    }
}
