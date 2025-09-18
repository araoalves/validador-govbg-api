package br.com.validadorgovbgapi.dtos;


import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Date;

@Data
@AllArgsConstructor
public class AssinaturaDTO {
    private boolean valid;
    private String signersName;
    private String signersDocumentId;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSZ", timezone = "America/Sao_Paulo")
    private Date signingDate;

    private String statusMessage;
}