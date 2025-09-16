package br.com.validadorgovbgapi;

import br.com.validadorgovbgapi.dtos.AssinaturaDTO;
import br.com.validadorgovbgapi.service.PdfSignatureValidator;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;

@RestController
public class SignatureValidationController {

    private final PdfSignatureValidator validator = new PdfSignatureValidator();

    @PostMapping("/validate")
    public AssinaturaDTO validateSignature(@RequestParam("file") MultipartFile file) throws IOException {
        File tempFile = File.createTempFile("pdf-", ".pdf");
        file.transferTo(tempFile);

        try {
            return validator.validatePdfSignature(tempFile.getAbsolutePath());
        } finally {
            tempFile.delete(); // Limpa o arquivo temporário
        }
    }
}