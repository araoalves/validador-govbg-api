package br.com.validadorgovbgapi.dtos;


import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Date;

@Data
@AllArgsConstructor
public class AssinaturaDTO {
    private boolean valid;
    private String signersName;
    private String signersDocumentId; // CPF ou CNPJ
    private Date signingDate;
    private String statusMessage;
}