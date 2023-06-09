package com.example.userservice.response;

import lombok.Builder;
import lombok.Data;

import java.io.Serializable;

@Data
@Builder
public class ResponseData implements Serializable {

    private String status;
    private String message;
    private Object data;
}
