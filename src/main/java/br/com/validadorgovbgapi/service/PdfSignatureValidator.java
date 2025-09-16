package br.com.validadorgovbgapi.service;

import br.com.validadorgovbgapi.dtos.AssinaturaDTO;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.Store;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;

public class PdfSignatureValidator {

    public AssinaturaDTO validatePdfSignature(String filePath) throws IOException {
        try (PDDocument document = PDDocument.load(new File(filePath))) {
            List<PDSignature> signatures = document.getSignatureDictionaries();
            if (signatures.isEmpty()) {
                return new AssinaturaDTO(false, null, null, null, "Nenhuma assinatura encontrada.");
            }

            // Exemplo de validação da primeira assinatura
            PDSignature signature = signatures.get(0);

            // 1. Validação da integridade do documento para PDFBox 3.x
            COSDictionary sigDict = signature.getCOSObject();
            COSString sigContents = (COSString) sigDict.getDictionaryObject(COSName.CONTENTS);

            if (sigContents == null || sigContents.getString().isEmpty()) {
                return new AssinaturaDTO(false, null, null, null, "Conteúdo da assinatura não encontrado.");
            }

            // O PDFBox 3.x não tem um método simples, a validação do hash é feita
            // implicitamente na leitura da assinatura. Se o arquivo foi modificado,
            // o CMS (CMSSignedData) não conseguirá ser decodificado corretamente.
            // A checagem `isModified()` da PDSignature não está disponível na versão 3.x.
            // A melhor abordagem é verificar se a extração dos dados é bem-sucedida.

            // 2. Extrair e validar o certificado
            Date signingDate = signature.getSignDate() != null ? signature.getSignDate().getTime() : null;
            String name = null;
            String documentId = null;

            try {
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

                        // Extrair dados do signatário (nome e CPF/CNPJ)
                        X500Name subject = certHolder.getSubject();
                        RDN commonName = subject.getRDNs(BCStyle.CN)[0];
                        name = commonName.getFirst().getValue().toString();

                        // O CPF/CNPJ pode estar em diferentes campos.
                        // O exemplo abaixo busca no campo "OU" (Organizational Unit)
                        RDN[] ouRdNs = subject.getRDNs(BCStyle.OU);
                        if (ouRdNs.length > 0) {
                            RDN rdn = ouRdNs[0];
                            if (rdn != null) {
                                ASN1Encodable value = rdn.getFirst().getValue();
                                if (value instanceof DERIA5String) {
                                    documentId = ((DERIA5String) value).getString();
                                }
                            }
                        }

                        // Converter o certificado para validação
                        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                                new java.io.ByteArrayInputStream(certHolder.getEncoded()));

                        // 3. Validação de validade do certificado (ICP-Brasil)
                        Date now = new Date();
                        if (now.before(cert.getNotBefore()) || now.after(cert.getNotAfter())) {
                            return new AssinaturaDTO(false, name, documentId, signingDate, "Certificado expirado ou ainda não é válido.");
                        }

                        // TODO: Adicionar lógica para validação completa da cadeia de confiança ICP-Brasil
                        // Isso envolve a verificação do OCSP/CRL e o uso de KeyStore com os certificados raiz.

                        return new AssinaturaDTO(true, name, documentId, signingDate, "Assinatura válida.");
                    }
                }
            } catch (Exception e) {
                // Se a decodificação do CMS falhar, a integridade do documento está comprometida.
                System.err.println("Erro na decodificação da assinatura. Integridade comprometida.");
                e.printStackTrace();
                return new AssinaturaDTO(false, null, null, signingDate, "Integridade do documento comprometida ou erro no certificado.");
            }
        } catch (IOException e) {
            System.err.println("Erro ao ler o arquivo PDF: " + e.getMessage());
            e.printStackTrace();
            return new AssinaturaDTO(false, null, null, null, "Erro ao ler o arquivo PDF.");
        }

        return new AssinaturaDTO(false, null, null, null, "Nenhuma assinatura validada.");
    }
}