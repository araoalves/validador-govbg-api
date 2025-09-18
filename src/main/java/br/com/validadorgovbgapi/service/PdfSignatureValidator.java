package br.com.validadorgovbgapi.service;

import br.com.validadorgovbgapi.dtos.AssinaturaDTO;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.Store;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.InputStream;

public class PdfSignatureValidator {

    // Método principal agora aceita um InputStream
    public List<AssinaturaDTO> validatePdfSignatures(InputStream pdfStream) throws IOException {
        List<AssinaturaDTO> signatureResults = new ArrayList<>();
        try (PDDocument document = PDDocument.load(pdfStream)) {
            List<PDSignature> signatures = document.getSignatureDictionaries();
            if (signatures.isEmpty()) {
                signatureResults.add(new AssinaturaDTO(false, null, null, null, "Nenhuma assinatura encontrada."));
                return signatureResults;
            }

            for (PDSignature signature : signatures) {
                AssinaturaDTO result = processSingleSignature(signature);
                signatureResults.add(result);
            }

        } catch (IOException e) {
            System.err.println("Erro ao ler o fluxo de dados do PDF: " + e.getMessage());
            e.printStackTrace();
            signatureResults.add(new AssinaturaDTO(false, null, null, null, "Erro ao ler o arquivo PDF."));
        }

        if (signatureResults.isEmpty()) {
            signatureResults.add(new AssinaturaDTO(false, null, null, null, "Nenhuma assinatura validada."));
        }

        return signatureResults;
    }

    private AssinaturaDTO processSingleSignature(PDSignature signature) {
        try {
            COSDictionary sigDict = signature.getCOSObject();
            COSString sigContents = (COSString) sigDict.getDictionaryObject(COSName.CONTENTS);

            if (sigContents == null || sigContents.getString().isEmpty()) {
                return new AssinaturaDTO(false, null, null, null, "Conteúdo da assinatura não encontrado.");
            }

            Date signingDate = null;
            if (signature.getSignDate() != null) {
                ZonedDateTime zonedDateTime = signature.getSignDate().toInstant().atZone(ZoneId.of("America/Sao_Paulo"));
                signingDate = Date.from(zonedDateTime.toInstant());
            }

            String name = null;
            String documentId = null;

            CMSSignedData cmsSignedData = new CMSSignedData(signature.getContents());
            Store<X509CertificateHolder> certs = cmsSignedData.getCertificates();
            Collection<SignerInformation> signers = cmsSignedData.getSignerInfos().getSigners();

            if (signers.isEmpty()) {
                return new AssinaturaDTO(false, null, null, signingDate, "Signatário não encontrado.");
            }

            for (SignerInformation signer : signers) {
                Collection<X509CertificateHolder> certificateHolders = certs.getMatches(signer.getSID());
                if (!certificateHolders.isEmpty()) {
                    X509CertificateHolder certHolder = certificateHolders.iterator().next();

                    X500Name subject = certHolder.getSubject();

                    RDN[] commonNameRDNs = subject.getRDNs(BCStyle.CN);
                    if (commonNameRDNs.length > 0) {
                        name = commonNameRDNs[0].getFirst().getValue().toString();
                    }

                    documentId = extractDocumentId(subject, certHolder);

                    X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                            new java.io.ByteArrayInputStream(certHolder.getEncoded()));

                    Date now = new Date();
                    if (now.before(cert.getNotBefore()) || now.after(cert.getNotAfter())) {
                        return new AssinaturaDTO(false, name, documentId, signingDate, "Certificado expirado ou ainda não é válido.");
                    }

                    return new AssinaturaDTO(true, name, documentId, signingDate, "Assinatura válida.");
                }
            }
        } catch (Exception e) {
            System.err.println("Erro na decodificação da assinatura. Integridade comprometida.");
            e.printStackTrace();
            return new AssinaturaDTO(false, null, null, null, "Integridade do documento comprometida ou erro no certificado.");
        }
        return new AssinaturaDTO(false, null, null, null, "Nenhuma assinatura validada.");
    }

    private String extractDocumentId(X500Name subject, X509CertificateHolder certHolder) throws IOException {
        String documentId = null;
        RDN[] allRDNs = subject.getRDNs();
        for (RDN rdn : allRDNs) {
            AttributeTypeAndValue[] atv = rdn.getTypesAndValues();
            if (atv.length > 0) {
                ASN1ObjectIdentifier oid = atv[0].getType();
                String value = atv[0].getValue().toString();
                if (oid.getId().equals(BCStyle.SERIALNUMBER.getId())) {
                    documentId = value;
                    break;
                }
                if (oid.getId().equals("2.16.76.1.3.3") || oid.getId().equals("2.16.76.1.3.4")) {
                    documentId = value;
                    break;
                }
            }
        }
        if (documentId == null) {
            Extension sanExtension = certHolder.getExtension(Extension.subjectAlternativeName);
            if (sanExtension != null) {
                byte[] extBytes = sanExtension.getExtnValue().getOctets();
                String extString = new String(extBytes);
                documentId = findDocumentIdInString(extString);
                if (documentId != null) {
                    return documentId;
                }
            }
        }
        if (documentId == null) {
            Pattern pattern = Pattern.compile("(\\d{11}|\\d{14})");
            Matcher matcher = pattern.matcher(subject.toString());
            if (matcher.find()) {
                documentId = matcher.group();
            }
        }
        return documentId;
    }

    private String findDocumentIdInString(String text) {
        String numericString = text.replaceAll("[^0-9]", "");
        if (numericString.length() >= 11) {
            String potentialDoc = numericString.substring(10);
            Pattern pattern = Pattern.compile("(\\d{11}|\\d{14})");
            Matcher matcher = pattern.matcher(potentialDoc);
            if (matcher.find()) {
                return matcher.group();
            }
        }
        return null;
    }
}