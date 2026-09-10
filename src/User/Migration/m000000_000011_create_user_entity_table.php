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

use yii\db\Migration;

/**
 * Handles the creation of the table `{{%user_entity}}` that allows user to use passkeys for logging in.
 */
class m000000_000011_create_user_entity_table extends Migration
{
    /**
     * {@inheritdoc}
     */
    public function safeUp()
    {
        $this->createTable('{{%user_entity}}', [
            'id' => $this->primaryKey(),
            'user_id' => $this->integer()->notNull(),
            // base64url-encoded credential id (~4/3 of the raw byte length). 512 covers every
            // authenticator seen in practice; resident keys (which this feature requires) use short
            // random ids. Kept short enough to be a UNIQUE index under utf8mb4.
            'credential_id' => $this->string(512)->notNull(),
            'public_key' => $this->text()->notNull(),
            'sign_count' => $this->bigInteger()->notNull()->defaultValue(0),
            'type' => $this->string(32)->notNull(),
            'attestation_type' => $this->string(32)->notNull()->defaultValue('none'),
            // user-agent hint, not a stable identifier
            'device_id' => $this->string(512)->null(),
            // UNIX timestamps, consistent with {{%user}} / {{%token}}
            'created_at' => $this->integer()->notNull(),
            'last_used_at' => $this->integer()->null(),
            'name' => $this->string(128)->null(),
        ]);

        // credential_id is looked up on every (anonymous) login attempt and must be globally unique;
        // user_id is filtered by the management UI.
        $this->createIndex('idx-user_entity-credential_id', '{{%user_entity}}', 'credential_id', true);
        $this->createIndex('idx-user_entity-user_id', '{{%user_entity}}', 'user_id');

        $this->addForeignKey(
            'fk_user_entity_user',
            '{{%user_entity}}',
            'user_id',
            '{{%user}}',
            'id',
            'CASCADE',
            'RESTRICT'
        );
    }

    public function safeDown()
    {
        $this->dropForeignKey('fk_user_entity_user', '{{%user_entity}}');
        $this->dropTable('{{%user_entity}}');
    }
}
