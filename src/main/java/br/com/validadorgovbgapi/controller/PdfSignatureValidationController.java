package br.com.validadorgovbgapi.controller;

import br.com.validadorgovbgapi.dtos.ArquivoDTO;
import br.com.validadorgovbgapi.dtos.AssinaturaDTO;
import br.com.validadorgovbgapi.service.PdfSignatureValidator;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.List;

@RestController
@RequestMapping("/api/pdf")
public class PdfSignatureValidationController {

    private final PdfSignatureValidator validator = new PdfSignatureValidator();

    @PostMapping("/validate-signatures")
    public ResponseEntity<List<AssinaturaDTO>> validatePdfSignatures(@RequestBody ArquivoDTO arquivo) {
        if (arquivo.getBase64File() == null || arquivo.getBase64File().isEmpty()) {
            return ResponseEntity.badRequest().body(null);
        }

        try {
            byte[] fileBytes = Base64.getDecoder().decode(arquivo.getBase64File());

            try (ByteArrayInputStream inputStream = new ByteArrayInputStream(fileBytes)) {
                List<AssinaturaDTO> results = validator.validatePdfSignatures(inputStream);
                return ResponseEntity.ok(results);
            }
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().body(null);
        }
    }
}