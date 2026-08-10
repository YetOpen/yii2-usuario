<?php

namespace Da\User\Repository;

use Da\User\Helper\UserEntityHelper;
use Da\User\Model\UserEntity;
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;

class UserEntityCredentialSourceRepository
{
    public $userEntityHelper;

    public function __construct()
    {
        $this->userEntityHelper = new UserEntityHelper();
    }

    public function findOneByCredentialId(string $credentialIdB64): ?PublicKeyCredentialSource
    {
        //find the user by credential_id
        $model = UserEntity::findOne(['credential_id' => $credentialIdB64]);
        if (!$model) {
            return null;
        }

        // aaguid and trustPath are attestation-time (registration) concerns: none of the login/
        // assertion ceremony steps read them, so a placeholder is sufficient here. The real values
        // were already verified once, at registration time, by AuthenticatorAttestationResponseValidator.
        return new PublicKeyCredentialSource(
            $model->credential_id,
            'public-key',
            [], // transports
            $model->attestation_format ?? 'none',
            new EmptyTrustPath(),
            Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            $this->userEntityHelper->base64UrlDecode($model->public_key),
            (string)$model->user_id,
            (int)$model->sign_count,
            null,
            null,
            null,
            null
        );
    }
}
