<?php

namespace Da\User\Helper;

use Cose\Algorithm\Manager as CoseAlgorithmManager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\RSA\RS256;
use Da\User\Model\UserEntity;
use Da\User\Traits\ModuleAwareTrait;
use Random\RandomException;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Yii;


/**
 *
 */

class UserEntityHelper
{
    use ModuleAwareTrait;
    public function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }

    public function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    function utf8ize($data)
    {
        if (is_array($data)) {
            foreach ($data as $key => $value) {
                $data[$key] = $this->utf8ize($value);
            }
        } elseif (is_string($data)) {
            return mb_convert_encoding($data, 'UTF-8', 'UTF-8');
        }
        return $data;
    }

    /**
     * Builds the CeremonyStepManagerFactory shared by registration and login validators.
     * Configures the exact origin (scheme+host+port) allowed and the attestation formats supported.
     */
    private function buildAttestationStatementSupportManager(): AttestationStatementSupportManager
    {
        $algorithmManager = CoseAlgorithmManager::create()->add(ES256::create(), RS256::create());
        return new AttestationStatementSupportManager([
            new NoneAttestationStatementSupport(),
            new PackedAttestationStatementSupport($algorithmManager),
            new AndroidKeyAttestationStatementSupport(),
            new TPMAttestationStatementSupport(),
        ]);
    }

    private function buildCeremonyStepManagerFactory(): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        // Full origin (scheme + host [+ port]), not just the hostname: CheckAllowedOrigins compares
        // against the full "origin" reported by the browser (see CVE-2026-30964 for what goes wrong
        // when only the host is compared).
        $factory->setAllowedOrigins([Yii::$app->request->hostInfo]);
        $factory->setAttestationStatementSupportManager($this->buildAttestationStatementSupportManager());

        return $factory;
    }

    /**
     * Loader used to turn the raw (base64url) attestationObject sent by the browser during
     * registration into a parsed AttestationObject, before it's handed to the attestation validator.
     */
    public function createAttestationObjectLoader(): \Webauthn\AttestationStatement\AttestationObjectLoader
    {
        return new \Webauthn\AttestationStatement\AttestationObjectLoader($this->buildAttestationStatementSupportManager());
    }

    /**
     * Validator for the registration ceremony: verifies challenge, origin, rpId hash,
     * attestation statement/signature and algorithm against what the server requested.
     */
    public function createAttestationValidator(): AuthenticatorAttestationResponseValidator
    {
        return new AuthenticatorAttestationResponseValidator($this->buildCeremonyStepManagerFactory()->creationCeremony());
    }

    /**
     * Validator for the login ceremony: verifies challenge, origin, rpId hash, and critically
     * the assertion signature and the sign counter (anti-cloning) against the stored credential.
     */
    function createAssertionValidator(): AuthenticatorAssertionResponseValidator
    {
        return new AuthenticatorAssertionResponseValidator($this->buildCeremonyStepManagerFactory()->requestCeremony());
    }

    /**
     * @throws RandomException
     */
    public function challengeGeneration(): array
    {
        //effective generation of the challenge
        $challengeRaw = random_bytes(32);
        $challengeBase64 = $this->base64UrlEncode($challengeRaw);
        $this->storeChallenge($challengeBase64);

        return [
            'success' => true,
            'challenge' => $challengeBase64,
            'rpId' => Yii::$app->request->hostName,
            // Discoverable/resident-key flow: we deliberately do NOT enumerate credential ids here.
            // The browser/authenticator itself picks among the resident credentials it holds for
            // this rpId, so the server never needs to (and must not) hand out every registered
            // credential_id to an anonymous caller.
            'allowCredentials' => [],
        ];
    }

    /**
     * Generates a server-side challenge for the registration ceremony, scoped to the current user.
     * @throws RandomException
     */
    public function challengeGenerationForRegistration(): array
    {
        $user = Yii::$app->user->identity;

        $challengeRaw = random_bytes(32);
        $challengeBase64 = $this->base64UrlEncode($challengeRaw);
        $this->storeChallenge($challengeBase64);

        $existingPasskeys = UserEntity::find()->andWhere(['user_id' => $user->id])->all();
        $excludeCredentials = array_map(fn($pk) => [
            'type' => 'public-key',
            'id' => $pk->credential_id,
        ], $existingPasskeys);

        return [
            'success' => true,
            'challenge' => $challengeBase64,
            'rp' => [
                'id' => Yii::$app->request->hostName,
                'name' => Yii::$app->name ?: Yii::$app->request->hostName,
            ],
            'user' => [
                'id' => (string) $user->id,
                'name' => $user->username,
                'displayName' => $user->username,
            ],
            'pubKeyCredParams' => [
                ['type' => 'public-key', 'alg' => -7],
                ['type' => 'public-key', 'alg' => -257],
            ],
            'excludeCredentials' => $excludeCredentials,
            // 'none': avoids requiring a FIDO Metadata Service repository to validate the
            // attestation certificate chain, which we don't need for a login feature.
            'attestation' => 'none',
            'timeout' => 60000,
        ];
    }

    //this function checks if the current can access the passkey pages
    public function checkAccessConditions() : bool
    {
        $module = $this->getModule();
        if(Yii::$app->user->isGuest||!$module->enablePasskeyLogin){
            return false;
        }
        return true;
    }

    public function loadTableData(){
        $dataProvider = new \yii\data\ActiveDataProvider([
            'query' => \Da\User\Model\UserEntity::find()->Andwhere(['user_id' => Yii::$app->user->id]),
            'pagination' => [
                'pageSize' => 10,
            ],
            'sort' => [
                'defaultOrder' => [
                    'created_at' => SORT_DESC,
                ]
            ],
        ]);
        return $dataProvider;
    }

    //this function puts the challenge as a session variable
    public function storeChallenge(?string $challengeBase64): void
    {
        Yii::$app->session->set('webauthn_challenge', $challengeBase64);
    }
    //this function is for retrieve the challenge saved in the session
    public function retrieveChallenge(): ?string
    {
        return Yii::$app->session->get('webauthn_challenge') ?: null;
    }
}
