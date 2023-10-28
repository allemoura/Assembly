;Alessandra Maria Ramos Barros de Moura
.686
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\masm32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\masm32.lib

.data?
  handleOut dd ?
  handleInput dd ?
  fileHandle dd ?
  newFileHandle dd ?
  bufferLeitura dd ?
  bufferEscrita dd ?
  bufferNovoArquivo byte 512 dup(?)
  tamanhoLeitura dd ?
  opcao dd ?
  contadorEscrita dd ?
  chave dd ?

.data
  mensagemEscolha db "Bem vindo a Cifra de Cesar!!\n\nEscolha uma opcao: Criptografar(1), Descriptografar(2), Sair(3)",0H
  menssagemNomeArquivo db "Digite o nome do arquivo",0H
  menssagemNovoArquivo db "Digite o nome do novo arquivo",0H
  mensagemChave db "Digite uma chave entre 1 e 20",0H
  entradaNomeArquivo db 50 DUP(0)
  entradaNomeNovoArquivo db 50 DUP(0)
  entradaChave db 4 DUP(0)
  entradaEscolha db 4 DUP(0)

.code
  ;funcao fornecida pelo professor para remover caracteres problematicos como CR ou LF
  RemoveCaracteres:
    mov esi, [ebp + 8]
    repete:
      mov al, [esi]
      inc esi
      cmp al, 13
      jne repete
    dec esi
    xor al, al
    mov [esi], al
    ret 4

  ;funcao que exibe mensagem e recebe um valor de entrada
  EntradaDeDados:
      push ebp
      mov ebp, esp
      mov ecx, DWORD PTR [ebp + 8]
      mov eax, DWORD PTR [ebp+12]

      invoke WriteConsole, handleOut, ecx, eax, addr bufferEscrita, NULL

      mov ecx, DWORD PTR [ebp + 16]
      mov eax, DWORD PTR [ebp+20]
   
      invoke ReadConsole, handleInput, ecx, eax, addr bufferLeitura, NULL

      push ecx
      call RemoveCaracteres
      mov esp, ebp
      pop ebp
    ret 16

  ;funcao para abrir arquivo base e criar o novo arquivo
  CriarEAbrirArquivos:
    invoke CreateFile, addr entradaNomeNovoArquivo, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    mov newFileHandle, eax
    invoke CreateFile, addr entradaNomeArquivo, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov fileHandle, eax
    ret

  ;funcao que criptografar os valores de uma leitura de arquivo somando o valor recebido de chave
  Criptografar:
    push ebp
    mov ebp, esp

    xor ecx, ecx
    mov esi, [ebp + 8]

    mov ebx, DWORD PTR [ebp+12]
    mov edx, DWORD PTR [ebp+16]
    somar:
      cmp ecx, ebx
      je sairCriptografar
      mov al, [esi]
      add eax, edx
      mov [esi], al
      inc ecx
      inc esi
      jmp somar
    sairCriptografar:
      mov esp, ebp
      pop ebp
      ret 12

  ;funcao que descriptografar os valores de uma leitura de arquivo subtraindo o valor recebido de chave
  Descriptografar:
    push ebp
    mov ebp, esp

    xor ecx, ecx
    mov esi, [ebp + 8]

    mov ebx, DWORD PTR [ebp+12]
    mov edx, DWORD PTR [ebp+16]
    subtrair:
      cmp ecx, ebx
      je sairDescriptografar
      mov al, [esi]
      sub eax, edx
      mov [esi], al
      inc ecx
      inc esi
      jmp subtrair
    sairDescriptografar:
      mov esp, ebp
      pop ebp
      ret 12

  ;limpa o buffer para as proximas leituras
  LimparBuffer:
    push ebp
    mov ebp, esp

    xor ecx, ecx
    mov esi, [ebp + 8]
    mov ebx, DWORD PTR [ebp+12]
    limpar:
      cmp ecx, ebx
      je sairLimpeza
      xor eax, eax
      mov [esi], eax
      inc esi
      inc ecx
      jne limpar

    sairLimpeza:
      mov esp, ebp
      pop ebp
      ret 8

  ;funcao de leitura do arquivo de 512 byte por vez do arquivo original e Criptografar ou Descriptografar e salva no novo arquivo criado
  LerESalvarArquivo:
    lerArquivo:
      invoke ReadFile, fileHandle, addr bufferNovoArquivo, 512, addr tamanhoLeitura, NULL 
    
    cmp tamanhoLeitura, 0;verefica se o arquivo chegou ao fim
    je fecharArquivos
    
    cmp opcao, 1
    je criptografarArquivo

    cmp opcao, 2
    je descriptografarArquivo    

    criptografarArquivo: 
      push chave
      push tamanhoLeitura
      push offset bufferNovoArquivo 
      call Criptografar
      jmp gravar
    descriptografarArquivo:
      push chave
      push tamanhoLeitura
      push offset bufferNovoArquivo
      call Descriptografar
    
    gravar:
      invoke WriteFile, newFileHandle, addr bufferNovoArquivo, tamanhoLeitura, addr contadorEscrita, NULL

    jmp lerArquivo
    ;fecha o arquivo original e o novo
    fecharArquivos:
      invoke CloseHandle, fileHandle
      invoke CloseHandle, newFileHandle

      push sizeof bufferNovoArquivo
      push offset bufferNovoArquivo

      call LimparBuffer
      ret

start:
  inicioPrograma:
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov handleOut, eax
    invoke GetStdHandle, STD_INPUT_HANDLE
    mov handleInput, eax

    push sizeof entradaEscolha
    push offset entradaEscolha
    push sizeof mensagemEscolha
    push offset mensagemEscolha

    call EntradaDeDados

    invoke atodw, addr entradaEscolha;converte o texto para numero
    mov opcao, eax

    cmp opcao, 3
    je finalizarAplicacao

    push sizeof entradaNomeArquivo
    push offset entradaNomeArquivo
    push sizeof menssagemNomeArquivo
    push offset menssagemNomeArquivo

    call EntradaDeDados

    push sizeof entradaNomeNovoArquivo
    push offset entradaNomeNovoArquivo
    push sizeof menssagemNovoArquivo
    push offset menssagemNovoArquivo

    call EntradaDeDados

    push sizeof entradaChave
    push offset entradaChave
    push sizeof mensagemChave
    push offset mensagemChave

    call EntradaDeDados

    invoke atodw, addr entradaChave
    mov chave, eax

    call CriarEAbrirArquivos
    call LerESalvarArquivo
    jmp inicioPrograma

  finalizarAplicacao:
    invoke ExitProcess, 0
end start