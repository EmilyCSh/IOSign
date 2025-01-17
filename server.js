const express = require('express');
const multer  = require('multer');
const path = require('path');
const fs = require('fs');
const unzipper = require('unzipper');
const { exec } = require('child_process');
const util = require('util');
const execAsync = util.promisify(exec);
const archiver = require('archiver');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT;
const OTAPROV = path.resolve(process.env.OTAPROV_PATH);
const KEY = path.resolve(process.env.KEY_PATH);
const PUBLIC = path.resolve(process.env.PUBLIC_PATH);
const WORK = path.resolve(process.env.WORK_PATH);
const URL = process.env.URL;
const ZIP_COMPRESSION = parseInt(process.env.ZIP_COMPRESSION, 10);

const validUdids = process.env.VALID_UDIDS ? process.env.VALID_UDIDS.split(',').map(udid => udid.trim().toUpperCase()) : [];

if (validUdids.length === 0) {
    console.error('No valid UDIDs found. Please define VALID_UDIDS.');
    process.exit(1);
}

app.use('/public', express.static(PUBLIC));

app.get('/', (req, res) => {
    res.sendFile(path.join('/app/index.html'));
});

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadPath = WORK;
        if (!fs.existsSync(uploadPath)){
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, `${WORK}/`);
    },
    filename: function (req, file, cb) {
        cb(null, `${Date.now()}_${uuidv4()}_${file.originalname}`);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 8 * 1024 * 1024 * 1024 },
    fileFilter: function (req, file, cb) {
        const filetypes = /ipa/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

        const mimetypes = [
            'application/octet-stream',
            'application/x-itunes-ipa'
        ];
        const mimetype = mimetypes.includes(file.mimetype);

        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Uploaded file is not a valid iOS IPA file.'));
        }
    }
});

const unzipIPA = async(filePath, outputDir) => {
    return fs.createReadStream(filePath)
    .pipe(unzipper.Extract({ path: outputDir }))
    .promise();
};

async function signIpa(workPath) {
    if (!workPath) {
        throw new Error('The workPath parameter is required.');
    }

    if (!fs.existsSync(workPath)) {
        throw new Error(`The specified working directory does not exist: ${workPath}`);
    }

    const env = { ...process.env, WINEDEBUG: '-all' };
    const command = `/zsign -m "${OTAPROV}" -k "${KEY}" -s "${workPath}"`;

    try {
        const { stdout, stderr } = await execAsync(command, { env });
        const SIGN_OUT = stdout + (stderr ? '\n' + stderr : '');

        let SIGN_STATUS = null;
        let BUNDLE_ID = null;
        let BUNDLE_VER = null;

        const lines = SIGN_OUT.split('\n');
        for (const line of lines) {
            if (line.includes('Signed OK!')) {
                SIGN_STATUS = 'Signed OK!';
            }

            if (line.includes('BundleId:')) {
                BUNDLE_ID = line.replace(/^.*BundleId:\s*/, '').trim();
            }

            if (line.includes('BundleVersion:')) {
                BUNDLE_VER = line.replace(/^.*BundleVersion:\s*/, '').trim();
            }
        }

        return { SIGN_STATUS, BUNDLE_ID, BUNDLE_VER };
    } catch (error) {
        const SIGN_OUT = error.stdout + (error.stderr ? '\n' + error.stderr : '');

        let SIGN_STATUS = null;
        let BUNDLE_ID = null;
        let BUNDLE_VER = null;

        const lines = SIGN_OUT.split('\n');
        for (const line of lines) {
            if (line.includes('Signed OK!')) {
                SIGN_STATUS = 'Signed OK!';
            }

            if (line.includes('BundleId:')) {
                BUNDLE_ID = line.replace(/^.*BundleId:\s*/, '').trim();
            }

            if (line.includes('BundleVer:')) {
                BUNDLE_VER = line.replace(/^.*BundleVer:\s*/, '').trim();
            }
        }

        return { SIGN_STATUS, BUNDLE_ID, BUNDLE_VER, SIGN_OUT };
    }
}

function createZip(sourceDir, outPath, compressionLevel) {
    return new Promise((resolve, reject) => {
        const output = fs.createWriteStream(outPath);
        const archive = archiver('zip', {
            zlib: { level: compressionLevel },
        });

        output.on('close', () => {
            resolve();
        });

        archive.on('error', (err) => {
            reject(err);
        });

        archive.pipe(output);
        archive.directory(sourceDir, false);
        archive.finalize();
    });
}

const escapeXml = (unsafe) => {
    return unsafe.replace(/[<>&'"]/g, (c) => {
        switch (c) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case '\'': return '&apos;';
            case '"': return '&quot;';
        }
    });
}

function createOtaPlist(ipaUrl, bundleId, bundleVersion, appTitle) {
    const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
    <key>items</key>
    <array>
    <dict>
    <key>assets</key>
    <array>
    <dict>
    <key>kind</key>
    <string>software-package</string>
    <key>url</key>
    <string>__IPA_URL__</string>
    </dict>
    </array>
    <key>metadata</key>
    <dict>
    <key>bundle-identifier</key>
    <string>__BUNDLE_IDENTIFIER__</string>
    <key>bundle-version</key>
    <string>__BUNDLE_VERSION__</string>
    <key>kind</key>
    <string>software</string>
    <key>title</key>
    <string>__APP_TITLE__</string>
    </dict>
    </dict>
    </array>
    </dict>
    </plist>`;

    const replacements = {
        '__IPA_URL__': escapeXml(ipaUrl),
        '__BUNDLE_IDENTIFIER__': escapeXml(bundleId),
        '__BUNDLE_VERSION__': escapeXml(bundleVersion),
        '__APP_TITLE__': escapeXml(appTitle),
    };

    let plistContent = plistTemplate;
    for (const [placeholder, value] of Object.entries(replacements)) {
        const regex = new RegExp(placeholder, 'g');
        plistContent = plistContent.replace(regex, value);
    }

    return plistContent;
}

app.get('/ota/:bundleId/:bundleVersion/:ipaFileName', async (req, res, next) => {
    try {
        const { bundleId, bundleVersion, ipaFileName } = req.params;
        const ipaUrl = encodeURI(`${URL}/public/${ipaFileName}`);

        const plistContent = createOtaPlist(ipaUrl, bundleId, bundleVersion, bundleId);

        res.setHeader('Content-Type', 'application/xml');
        res.send(plistContent);
    } catch (error) {
        console.error('Error in /ota endpoint:', error);
        next();
    }
});

app.post('/sign', upload.single('file'), async (req, res, next) => {
    try {
        const udid = req.body.udid;

        if (!udid) {
            return res.status(400).send({ message: 'Device UDID is missing.' });
        }

        // Sanitize and normalize the UDID
        const sanitizedUdid = udid.trim().toUpperCase();

        // Check if the UDID is in the list of valid UDIDs
        if (!validUdids.includes(sanitizedUdid)) {
            console.log(`Unauthorized UDID attempt: ${sanitizedUdid}`);
            return res.status(403).send({ message: 'Unauthorized UDID.' });
        }

        if (!req.file) {
            return res.status(400).send({ message: 'No file uploaded.' });
        }

        const sanitizedFileName = req.file.originalname.replace(/[^a-zA-Z0-9-_]/g, '_');
        const outputDirName = `${sanitizedUdid}_${sanitizedFileName}`;
        const outputDirPath = path.join(WORK, `${Date.now()}_${uuidv4()}_${outputDirName}`);
        const outputIPAName = `${Date.now()}_${uuidv4()}_${outputDirName}.ipa`;
        const outputIPAPath = path.join(PUBLIC, outputIPAName);

        await unzipIPA(req.file.path, outputDirPath);
        fs.unlink(req.file.path, (err) => {
            if (err) {
                console.error('Error deleting uploaded file:', err);
            }
        });

        let result = null;

        try {
            result = await signIpa(outputDirPath);
        } catch (err) {
            console.error('Generic error in signIpa:', err);
            return res.status(500).send({ message: 'An error occurred while processing your request.' });
        }

        if (result.SIGN_STATUS !== 'Signed OK!') {
            console.log('Signing failed.');
            console.log(result.SIGN_OUT);
            return res.status(500).send({ message: 'An error occurred while processing your request.' });
        }

        try {
            await createZip(outputDirPath, outputIPAPath, ZIP_COMPRESSION);
        } catch (zipErr) {
            console.error('Error creating ZIP archive:', zipErr);
            return res.status(500).send({ message: 'Error creating ZIP archive.' });
        }

        fs.rm(outputDirPath, { recursive: true, force: true }, (error) => {
            if (error) {
                console.error('Error deleting work directory:', error);
            }
        });

        res.status(200).send({
            message: 'IPA signed successfully.',
            ipa_url: encodeURI(`${URL}/public/${outputIPAName}`),
            ota_url: encodeURI(`${URL}/ota/${result.BUNDLE_ID}/${result.BUNDLE_VER}/${outputIPAName}`)
        });
    } catch (err) {
        console.error('Generic error in /sign endpoint:', err);
        next();
    }
});

app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).send({ message: 'An error occurred while processing your request.' });
});

app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});
