jQuery(function ($) {
    $.fn.bindPassKeyCreationSubmit = function () {
        // We expect the function to be called on a yii form
        const form = $(this)
        form.on('beforeSubmit', async function (e) {

            switch (form.data('creating-credentials')) {
                case undefined:
                    e.preventDefault()
                    form.data('creating-credentials', true)
                    await form.registerWithPasskey()
                    return false
                case true:
                    e.preventDefault()
                    return false
                case false:
                    return true
            }
        }).submit(function (e) {
            const prevent = form.data('creating-credentials')
            if (prevent === true || prevent === undefined) {
                e.preventDefault();
                return false;
            }
        })
    }

    $.fn.registerWithPasskey = async function () {

        function arrayBufferToBase64url(buffer) {
            return btoa(String.fromCharCode(...new Uint8Array(buffer)))
                .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        }

        function base64UrlToUint8Array(base64UrlString) {
            let base64 = base64UrlString.replace(/-/g, '+').replace(/_/g, '/');
            while (base64.length % 4) {
                base64 += '=';
            }
            const binaryString = atob(base64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes;
        }

        const csrfToken = yii.getCsrfToken();

        try {
            const challengeRes = await fetch(passkeyChallengeUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({})
            });
            const options = await challengeRes.json();
            if (!options.success) {
                alert(window.PasskeyRegisterMessages.genError.replace('{msg}', options.message || ''));
                $(this).data('creating-credentials', undefined);
                return false;
            }

            const publicKey = {
                challenge: base64UrlToUint8Array(options.challenge),
                rp: options.rp,
                user: {
                    id: new TextEncoder().encode(options.user.id),
                    name: options.user.name,
                    displayName: options.user.displayName
                },
                pubKeyCredParams: options.pubKeyCredParams,
                excludeCredentials: (options.excludeCredentials || []).map(cred => ({
                    id: base64UrlToUint8Array(cred.id),
                    type: cred.type
                })),
                authenticatorSelection: {
                    userVerification: "preferred", //with this option set as preferred we can login using also yubikeys
                    residentKey: "required", //login uses discoverable/resident credentials only (no server-side allowCredentials list)
                    requireResidentKey: true //legacy alias for older browsers that don't understand residentKey
                },
                timeout: options.timeout || 60000,
                // server verifies with attestation 'none'; never request a stronger conveyance here
                attestation: options.attestation || "none"
            };

            const credential = await navigator.credentials.create({ publicKey });

            if (!credential?.response) {
                throw new Error(window.PasskeyRegisterMessages.invalidCr);
            }

            $('#credential_id').val(arrayBufferToBase64url(credential.rawId));
            $('#public_key').val(arrayBufferToBase64url(credential.response.attestationObject));
            $('#client_data_json').val(arrayBufferToBase64url(credential.response.clientDataJSON));
            $(this).data('creating-credentials', false).submit();

            return true;
        } catch (err) {
            console.error(err);

            if (err.name === 'AbortError') {
            } else {
                alert(window.PasskeyRegisterMessages.genError.replace('{msg}', err.message));
                location.reload();
            }

            $(this).data('creating-credentials', undefined);

            return false;
        }
    };
});
