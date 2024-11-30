<?php
function verificar_certificado_autoassinado($certificado) {
    $conteudoCertificado = file_get_contents($certificado);
    if ($conteudoCertificado === false) {
        throw new Exception("Erro ao ler o arquivo do certificado.");
    }
    if (strpos($conteudoCertificado, '-----BEGIN CERTIFICATE-----') === false) {
        $conteudoCertificado = "-----BEGIN CERTIFICATE-----\n" .
            wordwrap(base64_encode($conteudoCertificado), 64, "\n", true) .
            "\n-----END CERTIFICATE-----";
    }
    $certificadoX509 = openssl_x509_parse($conteudoCertificado);
    if ($certificadoX509 === false) {
        throw new Exception("Erro ao processar o certificado.");
    }
    return $certificadoX509['subject'] === $certificadoX509['issuer'];
}
function carregar_certificado($caminho) {
    $conteudo = file_get_contents($caminho);
    if ($conteudo === false) {
        throw new Exception("Erro ao ler o certificado em: $caminho");
    }
    if (strpos($conteudo, '-----BEGIN CERTIFICATE-----') === false) {
        $conteudo = "-----BEGIN CERTIFICATE-----\n" .
            wordwrap(base64_encode($conteudo), 64, "\n", true) .
            "\n-----END CERTIFICATE-----";
    }
    return openssl_x509_parse($conteudo);
}
function extrair_cn_certificado($certificado) {
    $certificadoCaminho = __DIR__ . '/certs/' . $certificado;
    $conteudoCertificado = file_get_contents($certificadoCaminho);
    if ($conteudoCertificado === false) {
        throw new Exception("Erro ao ler o arquivo do certificado.");
    }
    if (strpos($conteudoCertificado, '-----BEGIN CERTIFICATE-----') === false) {
        $conteudoCertificado = "-----BEGIN CERTIFICATE-----\n" .
        wordwrap(base64_encode($conteudoCertificado), 64, "\n", true) .
        "\n-----END CERTIFICATE-----";
    }
    $certificadoInfo = openssl_x509_parse($conteudoCertificado);
    if ($certificadoInfo === false) {
        throw new Exception("Erro ao processar o certificado.");
    }
    if (isset($certificadoInfo['subject']['CN'])) {
        return $certificadoInfo['subject']['CN'];
    }
    return null;
}
function extrair_cn_certificado_upload($certificado) {
    $certificadoCaminho = __DIR__ . '/uploads/' . $certificado;
    $conteudoCertificado = file_get_contents($certificadoCaminho);
    if ($conteudoCertificado === false) {
        throw new Exception("Erro ao ler o arquivo do certificado.");
    }
    if (strpos($conteudoCertificado, '-----BEGIN CERTIFICATE-----') === false) {
        $conteudoCertificado = "-----BEGIN CERTIFICATE-----\n" .
        wordwrap(base64_encode($conteudoCertificado), 64, "\n", true) .
        "\n-----END CERTIFICATE-----";
    }
    $certificadoInfo = openssl_x509_parse($conteudoCertificado);
    if ($certificadoInfo === false) {
        throw new Exception("Erro ao processar o certificado.");
    }
    if (isset($certificadoInfo['subject']['CN'])) {
        return $certificadoInfo['subject']['CN'];
    }
    return null;
}
function verificar_validade($cert_path) {
    $conteudoCertificado = file_get_contents($cert_path);
    if ($conteudoCertificado === false) {
        throw new Exception("Erro ao ler o arquivo do certificado.");
    }
    if (strpos($conteudoCertificado, '-----BEGIN CERTIFICATE-----') === false) {
        $conteudoCertificado = "-----BEGIN CERTIFICATE-----\n" .
            wordwrap(base64_encode($conteudoCertificado), 64, "\n", true) .
            "\n-----END CERTIFICATE-----";
    }
    $certificadoInfo = openssl_x509_parse($conteudoCertificado);
    if ($certificadoInfo === false) {
        throw new Exception("Erro ao processar o certificado.");
    }
    $validFrom = $certificadoInfo['validFrom_time_t'] ?? null;
    $validTo = $certificadoInfo['validTo_time_t'] ?? null;
    if ($validFrom === null || $validTo === null) {
        throw new Exception("Não foi possível obter as datas de validade do certificado.");
    }
    $agora = time();
    return $agora >= $validFrom && $agora <= $validTo;
}
function verificar_ski_certificados($cert_path1, $cert_path2) {
    $data1 = carregar_certificado($cert_path1);
    $data2 = carregar_certificado($cert_path2);
    if (!$data1 || !$data2) {
        throw new Exception("Erro ao carregar ou analisar os certificados.");
    }
    $aki1 = $data1['extensions']['subjectKeyIdentifier'] ?? null;
    $aki2 = $data2['extensions']['subjectKeyIdentifier'] ?? null;
    if (!$aki1 || !$aki2) {
        throw new Exception("Um ou ambos os certificados não possuem Subject Key Identifier (AKI).");
    }
    $aki1 = trim(str_replace('keyid:', '', $aki1));
    $aki2 = trim(str_replace('keyid:', '', $aki2));
    return $aki1 === $aki2;
}
function verificar_ski_aki($root_ca_path, $sub_ca_path) {
    $root_ca_info = carregar_certificado($root_ca_path);
    $sub_ca_info = carregar_certificado($sub_ca_path);
    if (isset($root_ca_info['extensions']['subjectKeyIdentifier'])) {
        $ski_root = str_replace([' ', ':'], '', $root_ca_info['extensions']['subjectKeyIdentifier']);
    } else {
        throw new Exception("Subject Key Identifier não encontrado na Root CA.");
    }
    if (isset($sub_ca_info['extensions']['authorityKeyIdentifier'])) {
        $aki_sub = str_replace([' ', ':', 'keyid:', 'keyid'], '', $sub_ca_info['extensions']['authorityKeyIdentifier']);
    } else {
        throw new Exception("Authority Key Identifier não encontrado na Subordinate CA.");
    }
    return trim($ski_root) === trim($aki_sub);
}
if($_POST["funcao"] == "adicionar"){
    $upload_dir = __DIR__ . '/certs/';
    $nome_arquivo = basename($_FILES['certificado']['name']);
    $caminho_arquivo = $upload_dir . $nome_arquivo;
    move_uploaded_file($_FILES['certificado']['tmp_name'], to: $caminho_arquivo);
    $certificado_final = $nome_arquivo;
    $pasta_certs = __DIR__ . '/certs';
    function extrair_ca_issuer_url($certificado) {
        $certificado = __DIR__ . '/certs/'.$certificado;
        $certificadovalue = file_get_contents($certificado);
        if (strpos($certificadovalue, '-----BEGIN CERTIFICATE-----') === false) {
            $conteudoBase64 = base64_encode($certificadovalue);
            $certificadoPEM = "-----BEGIN CERTIFICATE-----\n";
            $certificadoPEM .= wordwrap($conteudoBase64, 64, "\n", true);
            $certificadoPEM .= "\n-----END CERTIFICATE-----";
            $certificadovalue = $certificadoPEM;
        }
        $certificadoResource = openssl_x509_read($certificadovalue);
        if ($certificadoResource !== false) {
            $certificadoInfo = openssl_x509_parse($certificadoResource);
            if (isset($certificadoInfo['extensions']['authorityInfoAccess'])) {
                $authorityInfoAccess = $certificadoInfo['extensions']['authorityInfoAccess'];
                if (preg_match('/CA Issuers - URI:(\S+)/', $authorityInfoAccess, $matches)) {
                    return $matches[1];
                } else {
                    return null;
                }
            } else {
                return null;
            }
        }else{
            return null;
        }
    }
    function baixar_certificado($url, $nome_arquivo) {
        $headers = @get_headers($url);
        if ($headers && strpos($headers[0], '200') !== false) {
            $cert_data = file_get_contents($url);
            if ($cert_data === false) {
                echo "Erro ao baixar o certificado de $url\n";
                return false;
            }
            $nome_arquivo = preg_replace('/\.[^.\s]{2,4}$/', '.crt', $nome_arquivo);
            file_put_contents($nome_arquivo, $cert_data);
            return true;
        }else{
            return false;
        }
    }
    function construir_cadeia($certificado_final, $pasta_certs) {
        $cadeia = [];
        $cert_atual = $certificado_final;
        $certificado_inicial = $certificado_final;
        $ultimo_certificado_baixado = null;
        $cert_raiz = $certificado_inicial;
        $i = 1;
        while (true) {
            $url_intermediario = extrair_ca_issuer_url($cert_atual);
            if($url_intermediario === null && count($cadeia) == 0){
                if(!verificar_certificado_autoassinado(__DIR__ . "/certs/" .$cert_atual)){
                    echo "CA Issuers URI Indisponível. Não foi possível encontrar a Root CA usando o certificado informado.";
                    unlink(__DIR__ . "/certs/" . $certificado_final);
                    die;
                }
            }
            $cadeia[] = $cert_atual;
            if ($url_intermediario === null) {
                echo "Caminho de certificação concluído com sucesso.<br>";
                $cert_raiz = end($cadeia);
                foreach ($cadeia as $cert) {
                    if ($cert !== $cert_raiz) {
                        unlink("$pasta_certs/$cert");
                    }
                }
                $cadeia = [$cert_raiz];
                break;
            }
            $nome_intermediario = basename(parse_url($url_intermediario, PHP_URL_PATH));
            if($nome_intermediario == ""){
                $nome_intermediario = "certificado".$i.".crt";
                $i++;
            }
            if (!file_exists("$pasta_certs/$nome_intermediario")) {
                if (!baixar_certificado($url_intermediario, "$pasta_certs/$nome_intermediario")) {
                    echo "Erro ao baixar o certificado intermediário.<br>";
                    break;
                }
            }
            $cert_atual = "$nome_intermediario";
            $ultimo_certificado_baixado = basename(parse_url($url_intermediario, PHP_URL_PATH));
        }
        $cn = extrair_cn_certificado($cert_raiz);
        if(!is_null($cn)){
            rename( $pasta_certs . '/' . $cert_raiz, $pasta_certs . '/' . $cn . '.crt');
            echo "Certificado raiz identificado: $cn.crt<br>";
        }else{
            rename( $pasta_certs . '/' . $cert_raiz, $pasta_certs . '/' . $certificado_inicial);
            echo "Certificado raiz identificado: $certificado_inicial<br>";
        }  
        echo "<br><br><a href='index.php'>Voltar</a>";
    }
    construir_cadeia($certificado_final, $pasta_certs);
}else{
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $certs_dir = __DIR__ . '/certs/';
        $upload_dir = __DIR__ . '/uploads/';
        $nome_certificado = basename($_FILES['certificado']['name']);
        $caminho_certificado = $upload_dir . $nome_certificado;
        move_uploaded_file($_FILES['certificado']['tmp_name'], $caminho_certificado);

        $cas_confiaveis = $_POST['ca_select'];

        function extrair_ca_issuer_url($certificado) {
            $certificadovalue = file_get_contents($certificado);
            if (strpos($certificadovalue, '-----BEGIN CERTIFICATE-----') === false) {
                $conteudoBase64 = base64_encode($certificadovalue);
                $certificadoPEM = "-----BEGIN CERTIFICATE-----\n";
                $certificadoPEM .= wordwrap($conteudoBase64, 64, "\n", true);
                $certificadoPEM .= "\n-----END CERTIFICATE-----";
                $certificadovalue = $certificadoPEM;
            }
            $certificadoResource = openssl_x509_read($certificadovalue);
            if ($certificadoResource !== false) {
                $certificadoInfo = openssl_x509_parse($certificadoResource);        
                if (isset($certificadoInfo['extensions']['authorityInfoAccess'])) {
                    $authorityInfoAccess = $certificadoInfo['extensions']['authorityInfoAccess'];
                    if (preg_match('/CA Issuers - URI:(\S+)/', $authorityInfoAccess, $matches)) {
                        return $matches[1];
                    } else {
                        return null;
                    }
                } else {
                    return null;
                }
            }else{
                return null;
            }
        }
        function baixar_certificado($url, $nome_arquivo) {
            $headers = @get_headers($url);
            if ($headers && strpos($headers[0], '200') !== false) {
                $cert_data = file_get_contents($url);
                if ($cert_data === false) {
                    return false;
                }
                $nome_arquivo = preg_replace('/\.[^.\s]{2,4}$/', '.crt', $nome_arquivo);
                file_put_contents($nome_arquivo, $cert_data);
                return true;
            }else{
                return false;
            }
        }
        function construir_cadeia($certificado_inicial, $pasta_certs) {
            $cadeia = [];
            $cert_atual = $certificado_inicial;
            $i = 1;
            while (true) {
                $url_intermediario = extrair_ca_issuer_url($cert_atual);
                $cadeia[] = $cert_atual;
                if ($url_intermediario === null) {
                    break;
                }
                $nome_intermediario = basename(parse_url($url_intermediario, PHP_URL_PATH));
                if($nome_intermediario == ""){
                    $nome_intermediario = "certificado".$i.".crt";
                    $i++;
                }
                $caminho_intermediario = $pasta_certs . $nome_intermediario;
                if (!file_exists($caminho_intermediario)) {
                    if (!baixar_certificado($url_intermediario, $caminho_intermediario)) {
                        break;
                    }
                }
                $cert_atual = $caminho_intermediario;
            }
            return $cadeia;
        }
        $cadeia = construir_cadeia($caminho_certificado, $upload_dir);
        if(count($cadeia) > 0){
            $raiz_da_cadeia = end($cadeia);
            $raiz_valida = false;
            $sem_root = false;
            $root = "";
            $root_que_validou = "";
            foreach ($cas_confiaveis as $ca) {
                if ((hash_file('sha256', $certs_dir . $ca) === hash_file('sha256', $raiz_da_cadeia)) || verificar_ski_certificados($certs_dir . $ca, $raiz_da_cadeia)) {
                    $raiz_valida = true;
                    $root_que_validou = extrair_cn_certificado($ca);
                    break;
                }elseif(!verificar_certificado_autoassinado($raiz_da_cadeia)){
                    if(verificar_ski_aki($certs_dir . $ca, $raiz_da_cadeia)){
                        $raiz_valida = true;
                        $sem_root = true;
                        $root = $ca;
                        $root_que_validou = extrair_cn_certificado($ca);
                        break;
                    }
                }
            }
            foreach ($cadeia as $cert) {
                if(!verificar_validade($cert)){
                    $raiz_valida = false;
                }
            }
            echo "Caminho de certificação:<br>";
            $espacos = 0;
            if($sem_root){
                if(!verificar_validade($certs_dir.$root)){
                    $raiz_valida = false;
                }
                $cn = extrair_cn_certificado($root);
                if(!is_null($cn)){
                    echo $cn."<br>";
                    $espacos++;
                }else{
                    echo $root."<br>";
                    $espacos++;
                }
            }
            for($i = count($cadeia) - 1; $i >= 0; $i--){
                $cn = extrair_cn_certificado_upload(basename($cadeia[$i]));
                if(!is_null($cn)){
                    echo str_repeat("&nbsp;", $espacos).$cn."<br>";
                    $espacos++;
                }else{
                    echo str_repeat("&nbsp;", $espacos).basename($cadeia[$i])."<br>";
                    $espacos++;
                }
            }
            foreach ($cadeia as $cert) {
                if (file_exists($cert)) {
                    unlink($cert);
                }
            }
            if ($raiz_valida) {
                echo "<br>Validado pela AC-Raiz: ".$root_que_validou."<br>Certificado válido!";
            } else {
                echo "<br>Certificado inválido!";
            }
        }
        echo "<br><br><a href='index.php'>Voltar</a>";
    }
}

