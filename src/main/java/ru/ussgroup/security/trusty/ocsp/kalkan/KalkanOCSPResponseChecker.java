package ru.ussgroup.security.trusty.ocsp.kalkan;

import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.DERObject;
import kz.gov.pki.kalkan.asn1.DEROctetString;
import kz.gov.pki.kalkan.asn1.ocsp.OCSPObjectIdentifiers;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.ocsp.*;
import ru.ussgroup.security.trusty.TrustyCertPathValidator;
import ru.ussgroup.security.trusty.TrustyUtils;
import ru.ussgroup.security.trusty.exception.TrustyOCSPCertificateException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNonceException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPUnknownProblemException;
import ru.ussgroup.security.trusty.ocsp.TrustyOCSPStatus;
import ru.ussgroup.security.trusty.ocsp.TrustyOCSPValidationResult;
import ru.ussgroup.security.trusty.repository.TrustyRepository;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * This class is thread-safe
 */
public class KalkanOCSPResponseChecker {
    static {
        if (Security.getProvider(KalkanProvider.PROVIDER_NAME) == null) Security.addProvider(new KalkanProvider());
    }

    private final TrustyCertPathValidator validator;

    public KalkanOCSPResponseChecker(TrustyRepository trustyRepository) {
        validator = new TrustyCertPathValidator(trustyRepository);
    }

    public TrustyOCSPValidationResult checkResponse(OCSPResp response, byte[] nonce) throws TrustyOCSPCertificateException, TrustyOCSPNonceException, TrustyOCSPUnknownProblemException {
        try {
            if (response.getStatus() != 0) {
                throw new RuntimeException("Unsuccessful request. Status: " + response.getStatus());
            }

            BasicOCSPResp brep;

            try {
                brep = (BasicOCSPResp) response.getResponseObject();
            } catch (OCSPException e) {
                throw new RuntimeException("Unsuccessful request.", e);
            }

            byte[] respNonceExt = brep.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId());

            if (respNonceExt != null) {
                try (ASN1InputStream asn1In1 = new ASN1InputStream(respNonceExt)) {
                    DERObject derObj = asn1In1.readObject();

                    byte[] extV = DEROctetString.getInstance(derObj).getOctets();

                    try (ASN1InputStream asn1In2 = new ASN1InputStream(extV)) {
                        derObj = asn1In2.readObject();
                        byte[] receivedNonce = DEROctetString.getInstance(derObj).getOctets();
                        if (!java.util.Arrays.equals(nonce, receivedNonce)) {
                            throw new TrustyOCSPNonceException("Expected nonce: " + Base64.getEncoder().encode(nonce) + ", but received: " + Base64.getEncoder().encode(receivedNonce));
                        }
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            } else {
                throw new TrustyOCSPNonceException("Nonce extension not found in response!");
            }

            X509Certificate ocspcert;

            try {
                ocspcert = brep.getCerts(KalkanProvider.PROVIDER_NAME)[0];
            } catch (NoSuchProviderException | OCSPException e) {
                throw new RuntimeException(e);
            }

            try {
                String base64 = TrustyUtils.toBase64(ocspcert);

                ocspcert = TrustyUtils.loadFromString(base64);//Загружаем с помощью стандартного джавовского провайдера

                validator.validate(ocspcert);
            } catch (Exception e1) {
                throw new TrustyOCSPCertificateException(e1);
            }

            try {
                if (!brep.verify(ocspcert.getPublicKey(), KalkanProvider.PROVIDER_NAME)) {
                    throw new RuntimeException("Unable to verify response");
                }
            } catch (NoSuchProviderException | OCSPException e) {
                throw new RuntimeException(e);
            }

            Map<BigInteger, TrustyOCSPStatus> statuses = new HashMap<>();

            for (SingleResp singleResp : brep.getResponses()) {
                Object status = singleResp.getCertStatus();

                if (status == null) {
                    statuses.put(singleResp.getCertID().getSerialNumber(), new TrustyOCSPStatus(TrustyOCSPStatus.GOOD));
                } else if (status instanceof RevokedStatus) {
                    int reason = 0;

                    if (((RevokedStatus) status).hasRevocationReason()) {
                        reason = ((RevokedStatus) status).getRevocationReason();
                    }

                    statuses.put(singleResp.getCertID().getSerialNumber(), new TrustyOCSPStatus(TrustyOCSPStatus.REVOKED, ((RevokedStatus) status).getRevocationTime(), reason));
                } else {
                    statuses.put(singleResp.getCertID().getSerialNumber(), new TrustyOCSPStatus(TrustyOCSPStatus.UNKNOWN));
                }
            }

            return new TrustyOCSPValidationResult(response, statuses);
        } catch (RuntimeException e) {
            throw new TrustyOCSPUnknownProblemException(e);
        }
    }
}
