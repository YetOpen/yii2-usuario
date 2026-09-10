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

    /**
     * @var UserEntity|null the row backing the last findOneByCredentialId() lookup, so callers can
     *                      reuse it instead of querying by credential_id a second time.
     */
    private $model;

    public function __construct()
    {
        $this->userEntityHelper = new UserEntityHelper();
    }

    public function getModel(): ?UserEntity
    {
        return $this->model;
    }

    public function findOneByCredentialId(string $credentialIdB64): ?PublicKeyCredentialSource
    {
        $this->model = UserEntity::findOne(['credential_id' => $credentialIdB64]);
        if ($this->model === null) {
            return null;
        }
        $model = $this->model;

        // aaguid and trustPath are attestation-time (registration) concerns: none of the login/
        // assertion ceremony steps read them, so a placeholder is sufficient here. The real values
        // were already verified once, at registration time, by AuthenticatorAttestationResponseValidator.
        return new PublicKeyCredentialSource(
            // The library contract for publicKeyCredentialId is raw bytes, not the base64url form we
            // store. No requestCeremony() step reads it while allowCredentials is empty, but decoding
            // it here keeps the object correct if a non-empty allow list is ever sent.
            $this->userEntityHelper->base64UrlDecode($model->credential_id),
            'public-key',
            [], // transports
            $model->attestation_type ?? 'none',
            new EmptyTrustPath(),
            Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            $this->userEntityHelper->base64UrlDecode($model->public_key),
            (string) $model->user_id,
            (int) $model->sign_count,
            null,
            null,
            null,
            null
        );
    }
}
