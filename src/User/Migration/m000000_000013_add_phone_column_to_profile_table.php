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
 * Adds `{{%profile}}.phone`: the user's mobile number, in international format, set by an
 * administrator. Indexed: applications look a user up by it.
 */
class m000000_000013_add_phone_column_to_profile_table extends Migration
{
    /**
     * {@inheritdoc}
     */
    public function safeUp()
    {
        $this->addColumn('{{%profile}}', 'phone', $this->string(16)->null());
        $this->createIndex('idx-profile-phone', '{{%profile}}', 'phone');
    }

    /**
     * {@inheritdoc}
     */
    public function safeDown()
    {
        $this->dropIndex('idx-profile-phone', '{{%profile}}');
        $this->dropColumn('{{%profile}}', 'phone');
    }
}
