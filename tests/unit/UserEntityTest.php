<?php

namespace tests\unit;

use Da\User\Model\UserEntity;

class UserEntityTest extends \Codeception\Test\Unit
{
    private function makeModel(array $overrides = []): UserEntity
    {
        return new UserEntity(array_merge([
            'user_id' => 1,
            'credential_id' => 'sampleCredentialId' . uniqid('', true),
            'public_key' => 'samplePublicKey',
            'sign_count' => 0,
            'type' => 'public-key',
            'attestation_type' => 'none',
            'device_id' => 'Test Device',
            'name' => 'TestPasskey',
            'created_at' => time(),
        ], $overrides));
    }

    public function testValidUserEntity()
    {
        $model = $this->makeModel();

        $this->assertTrue($model->validate(), 'Model should validate with correct data: ' . json_encode($model->getErrors()));
    }

    public function testInvalidAttestationType()
    {
        $model = $this->makeModel(['attestation_type' => 'invalid-type']);

        $this->assertFalse($model->validate(), 'Model should not validate with an unknown attestation type.');
        $this->assertArrayHasKey('attestation_type', $model->getErrors());
    }

    public function testNameTooShort()
    {
        $model = $this->makeModel(['name' => 'abc']);

        $this->assertFalse($model->validate(), 'Model should not validate with short name.');
        $this->assertArrayHasKey('name', $model->getErrors());
    }

    public function testNameInvalidCharacters()
    {
        $model = $this->makeModel(['name' => 'Invalid@Name']);

        $this->assertFalse($model->validate(), 'Model should not validate with invalid characters in name.');
        $this->assertArrayHasKey('name', $model->getErrors());
    }

    public function testTimestampsMustBeIntegers()
    {
        $model = $this->makeModel(['created_at' => '2024-01-01 10:00:00']);

        $this->assertFalse($model->validate(), 'created_at must be a UNIX timestamp.');
        $this->assertArrayHasKey('created_at', $model->getErrors());
    }
}
