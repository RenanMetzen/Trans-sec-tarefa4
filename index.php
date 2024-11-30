<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Teste de Certificado</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f4f4f9;
        }

        .container {
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }

        h1 {
            text-align: center;
            color: #333;
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            font-size: 16px;
            color: #333;
            display: block;
            margin-bottom: 8px;
        }

        input[type="text"], input[type="file"], select {
            width: 100%;
            padding: 10px;
            margin: 8px 0;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 14px;
        }

        input[type="submit"] {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 10px 20px;
            font-size: 16px;
            cursor: pointer;
            border-radius: 4px;
        }

        input[type="submit"]:hover {
            background-color: #45a049;
        }

        .form-section {
            margin-bottom: 40px;
        }

        .section-header {
            font-size: 18px;
            color: #555;
            margin-bottom: 10px;
        }

        .help-text {
            font-size: 12px;
            color: #777;
        }

        .alert {
            background-color: #ffcccb;
            color: #d8000c;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 20px;
        }

        .success {
            background-color: #d4edda;
            color: #155724;
        }

        .error {
            background-color: #f8d7da;
            color: #721c24;
        }
    </style>
</head>
<body>

<div class="container">
    <h1>Teste de Certificado</h1>

    <div class="form-section">
        <div class="section-header">Adicionar Nova CA Confiável</div>
        <form action="verificaCertificado.php" method="POST" enctype="multipart/form-data">
            <div class="form-group">
                <input type="hidden" id="funcao" name="funcao" value="adicionar">
                <label for="certificado">Selecione o Certificado da CA</label>
                <input type="file" id="certificado" name="certificado" required>
                <div class="help-text">Selecione um certificado de autoridade confiável para adicionar ao sistema.</div>
            </div>
            <input type="submit" value="Adicionar CA Confiável">
        </form>
    </div>

    <div class="form-section">
        <div class="section-header">Enviar Certificado para Teste</div>
        <form action="verificaCertificado.php" method="POST" enctype="multipart/form-data">
            <div class="form-group">
                <input type="hidden" id="funcao" name="funcao" value="validar">
                <label for="certificado">Selecione o Certificado para Testar</label>
                <input type="file" id="certificado" name="certificado" required>
                <div class="help-text">Escolha um certificado para testar a validade.</div>
            </div>
            <div class="form-group">
                <label for="ca_select">Escolha a CA Confiável</label>
<?php
                $certificados = array_diff(scandir(__DIR__ . '/certs'), array('..', '.'));

                echo '<select id="ca_select" name="ca_select[]" multiple required>';

                foreach ($certificados as $certificado) {
                    if (strpos($certificado, '.crt') !== false || strpos($certificado, '.cer') !== false) {
                        echo '<option value="' . htmlspecialchars($certificado) . '">' 
                            . htmlspecialchars($certificado) . '</option>';
                    }
                }

                echo '</select>';
                ?>
            </div>
            <input type="submit" value="Verificar Certificado">
        </form>
    </div>

    <div id="resultado" class="alert success" style="display:none;">
        Certificado validado com sucesso!
    </div>
    <div id="erro" class="alert error" style="display:none;">
        Erro ao validar certificado. Tente novamente.
    </div>
</div>

</body>
</html>
