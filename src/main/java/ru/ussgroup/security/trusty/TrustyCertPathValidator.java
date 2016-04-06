package ru.ussgroup.security.trusty;

import ru.ussgroup.security.trusty.repository.TrustyRepository;

import java.math.BigInteger;
import java.security.SignatureException;
import java.security.cert.*;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * This class is thread-safe
 */
public class TrustyCertPathValidator {
    private final TrustyRepository repository;

    public TrustyCertPathValidator(TrustyRepository repository) {
        this.repository = repository;
    }

    public CompletableFuture<Map<BigInteger, TrustyCertValidationCode>> validateAsync(Set<X509Certificate> certs) {
        return validateAsync(certs, new Date());
    }

    /**
     * @param date null is disable expire date verification
     */
    public CompletableFuture<Map<BigInteger, TrustyCertValidationCode>> validateAsync(Set<X509Certificate> certs, Date date) {
        return CompletableFuture.supplyAsync(() -> {
            return certs.parallelStream().collect(Collectors.toConcurrentMap(X509Certificate::getSerialNumber, c -> {
                try {
                    validate(c, date);

                    return TrustyCertValidationCode.SUCCESS;
                } catch (CertificateNotYetValidException e) {
                    return TrustyCertValidationCode.CERT_NOT_YET_VALID;
                } catch (CertificateExpiredException e) {
                    return TrustyCertValidationCode.CERT_EXPIRED;
                } catch (SignatureException e) {
                    return TrustyCertValidationCode.CERT_SIGNATURE_EXCEPTION;
                } catch (CertPathValidatorException e) {
                    return TrustyCertValidationCode.CERT_PATH_FAILED;
                }
            }));
        });
    }

    public void validate(X509Certificate cert) throws CertificateNotYetValidException, CertificateExpiredException, SignatureException, CertPathValidatorException {
        validate(cert, new Date());
    }

    /**
     * @param date null is disable expire date verification
     */
    public void validate(X509Certificate cert, Date date) throws CertificateNotYetValidException, CertificateExpiredException, SignatureException, CertPathValidatorException {
        try {
            PKIXBuilderParameters params = new PKIXBuilderParameters(repository.getTrustedCerts().stream().map(c -> new TrustAnchor(c, null)).collect(Collectors.toSet()), null);
            params.setRevocationEnabled(false);

            params.setDate(date != null ? date : cert.getNotBefore());

            CertPathValidator.getInstance("PKIX").validate(CertificateFactory.getInstance("X.509").generateCertPath(TrustyUtils.getCertPath(cert, repository)), params);
        } catch (Exception e) {
            //CertificateNotYetValidException.getReason не поддерживается калканом ((
            if (e.getCause() != null) {
                if (e.getCause() instanceof CertificateNotYetValidException) {
                    CertificateNotYetValidException e1 = (CertificateNotYetValidException) e.getCause();

                    throw e1;
                }

                if (e.getCause() instanceof CertificateExpiredException) {
                    CertificateExpiredException e1 = (CertificateExpiredException) e.getCause();

                    throw e1;
                }

                if (e.getCause() instanceof SignatureException) {//почему-то в случае с подделкой сертификата вместо этого исключения стало выбрасываться CertPathValidatorException
                    SignatureException e1 = (SignatureException) e.getCause();

                    throw e1;
                }
            }

            if (e instanceof CertPathValidatorException) {
                CertPathValidatorException e1 = (CertPathValidatorException) e;

                throw e1;
            }

            throw new CertPathValidatorException(e);
        }
    }
}
