import { errorHandling, telemetryData } from "./utils/middleware";
import { fetchUploadConfig, fetchSecurityConfig } from "./utils/sysConfig";
import { purgeCFCache } from "./utils/purgeCache";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";

let uploadConfig = {};
let securityConfig = {};
let rightAuthCode = null;
let moderateContentApiKey = null;

function UnauthorizedException(reason) {
    return new Response(reason, {
        status: 401,
        statusText: "Unauthorized",
        headers: {
            "Content-Type": "text/plain;charset=UTF-8",
            // Disables caching by default.
            "Cache-Control": "no-store",
            // Returns the "Content-Length" header for HTTP HEAD requests.
            "Content-Length": reason.length,
        },
    });
}

function isValidAuthCode(envAuthCode, authCode) {
    return authCode === envAuthCode;
}

function isAuthCodeDefined(authCode) {
    return authCode !== undefined && authCode !== null && authCode.trim() !== '';
}


function getCookieValue(cookies, name) {
    const match = cookies.match(new RegExp('(^| )' + name + '=([^;]+)'));
    return match ? decodeURIComponent(match[2]) : null;
}

function authCheck(env, url, request) {
    // 优先从请求 URL 获取 authCode
    let authCode = url.searchParams.get('authCode');
    // 如果 URL 中没有 authCode，从 Referer 中获取
    if (!authCode) {
        const referer = request.headers.get('Referer');
        if (referer) {
            try {
                const refererUrl = new URL(referer);
                authCode = new URLSearchParams(refererUrl.search).get('authCode');
            } catch (e) {
                console.error('Invalid referer URL:', e);
            }
        }
    }
    // 如果 Referer 中没有 authCode，从请求头中获取
    if (!authCode) {
        authCode = request.headers.get('authCode');
    }
    // 如果请求头中没有 authCode，从 Cookie 中获取
    if (!authCode) {
        const cookies = request.headers.get('Cookie');
        if (cookies) {
            authCode = getCookieValue(cookies, 'authCode');
        }
    }
    if (isAuthCodeDefined(rightAuthCode) && !isValidAuthCode(rightAuthCode, authCode)) {
        return false;
    }
    return true;
}

export async function onRequestPost(context) {  // Contents of context object
    const { request, env, params, waitUntil, next, data } = context;

    const url = new URL(request.url);
    const clonedRequest = await request.clone();

    // 读取安全配置
    securityConfig = await fetchSecurityConfig(env);
    rightAuthCode = securityConfig.auth.user.authCode;
    moderateContentApiKey = securityConfig.upload.moderate.apiKey;
    
    // 鉴权
    if (!authCheck(env, url, request)) {
        return UnauthorizedException('Unauthorized');
    }

    // 获得上传IP
    const uploadIp = request.headers.get("cf-connecting-ip") || request.headers.get("x-real-ip") || request.headers.get("x-forwarded-for") || request.headers.get("x-client-ip") || request.headers.get("x-host") || request.headers.get("x-originating-ip") || request.headers.get("x-cluster-client-ip") || request.headers.get("forwarded-for") || request.headers.get("forwarded") || request.headers.get("via") || request.headers.get("requester") || request.headers.get("true-client-ip") || request.headers.get("client-ip") || request.headers.get("x-remote-ip") || request.headers.get("x-originating-ip") || request.headers.get("fastly-client-ip") || request.headers.get("akamai-origin-hop") || request.headers.get("x-remote-ip") || request.headers.get("x-remote-addr") || request.headers.get("x-remote-host") || request.headers.get("x-client-ip") || request.headers.get("x-client-ips") || request.headers.get("x-client-ip")
    // 判断上传ip是否被封禁
    const isBlockedIp = await isBlockedUploadIp(env, uploadIp);
    if (isBlockedIp) {
        return new Response('Error: Your IP is blocked', { status: 403 });
    }
    // 获取IP地址
    const ipAddress = await getIPAddress(uploadIp);

    // 读取上传配置
    uploadConfig = await fetchUploadConfig(env);

    // 获得上传渠道
    const urlParamUploadChannel = url.searchParams.get('uploadChannel');
    // 获取上传文件夹路径
    let uploadFolder = url.searchParams.get('uploadFolder') || '';

    let uploadChannel = 'TelegramNew';
    switch (urlParamUploadChannel) {
        case 'telegram':
            uploadChannel = 'TelegramNew';
            break;
        case 'cfr2':
            uploadChannel = 'CloudflareR2';
            break;
        case 's3':
            uploadChannel = 'S3';
            break;
        case 'external':
            uploadChannel = 'External';
            break;
        default:
            uploadChannel = 'TelegramNew';
            break;
    }
    
    // 错误处理和遥测
    if (env.dev_mode === undefined || env.dev_mode === null || env.dev_mode !== 'true') {
        await errorHandling(context);
        telemetryData(context);
    }

    // img_url 未定义或为空的处理逻辑
    if (typeof env.img_url == "undefined" || env.img_url == null || env.img_url == "") {
        return new Response('Error: Please configure KV database', { status: 500 });
    }

    // 获取文件信息 或 处理 fetch action
    const time = new Date().getTime();
    const formdata = await clonedRequest.formData();
    let fileToUpload;
    let fileType;
    let fileName;
    let fileSize; // 文件大小，单位MB

    const action = url.searchParams.get('action');

    if (action === 'fetch') {
        const targetUrl = formdata.get('url');
        if (!targetUrl) {
            return new Response('Error: URL is required for fetch action', { status: 400 });
        }
        try {
            const response = await fetch(targetUrl);
            if (!response.ok) {
                throw new Error(`Failed to fetch URL: ${response.statusText}`);
            }
            const fetchedContentType = response.headers.get('content-type') || 'application/octet-stream';
            // 基础的文件名提取，可能需要更健壮的逻辑
            let fetchedFileName = targetUrl.substring(targetUrl.lastIndexOf('/') + 1).split(/[?#]/)[0];
            if (!fetchedFileName) { // 如果URL以/结尾或没有路径部分
                 // 尝试从 Content-Disposition 获取文件名
                 const disposition = response.headers.get('content-disposition');
                 const filenameMatch = disposition && disposition.match(/filename\*?=['"]?([^'";]+)['"]?/);
                 if (filenameMatch && filenameMatch[1]) {
                     fetchedFileName = decodeURIComponent(filenameMatch[1]);
                 } else {
                     fetchedFileName = `fetched_${time}`; // 备用名称
                 }
            }

            const fileContent = await response.blob();

            // 创建一个类似 File 的对象，因为后续代码可能依赖这些属性
            fileToUpload = fileContent; // 直接使用 Blob
            // 显式添加 name 属性，因为 Blob 本身没有
            Object.defineProperty(fileToUpload, 'name', {
                value: fetchedFileName,
                writable: true, // 如果需要后续修改
            });
            // fileToUpload.size 在 Blob 上已存在
            // fileToUpload.type 在 Blob 上已存在

            fileType = fileToUpload.type;
            fileName = fileToUpload.name;
            fileSize = (fileToUpload.size / 1024 / 1024).toFixed(2);

        } catch (error) {
            console.error('Fetch action error:', error);
            return new Response(`Error fetching URL: ${error.message}`, { status: 500 });
        }

    } else if (uploadChannel === 'External') {
        // 对于 External 渠道，我们不需要实际的文件内容，但需要设置一些元数据
        fileName = formdata.get('url') || `external_${time}`; // 使用 URL 或备用名
        fileType = 'external/link'; // 虚拟类型
        fileSize = 0;
        fileToUpload = null; // 标记没有实际文件
         // 检查 URL 是否存在
        if (!formdata.get('url')) {
            return new Response('Error: URL is required for external channel', { status: 400 });
        }
    }
    else {
        fileToUpload = formdata.get('file');
        if (!fileToUpload) {
             return new Response('Error: No file provided in form data', { status: 400 });
        }
        fileType = fileToUpload.type;
        fileName = fileToUpload.name;
        fileSize = (fileToUpload.size / 1024 / 1024).toFixed(2);
        // 检查fileType和fileName是否存在
        if (fileType === null || fileType === undefined || fileName === null || fileName === undefined) {
            return new Response('Error: fileType or fileName is wrong, check the integrity of this file!', { status: 400 });
        }
        // 从完整路径中提取文件名
        fileName = fileName.includes('/') ? fileName.substring(fileName.lastIndexOf('/') + 1) : fileName;
    }
    // 如果上传文件夹路径为空，尝试从文件名中获取
    if (uploadFolder === '' || uploadFolder === null || uploadFolder === undefined) {
        uploadFolder = fileName.split('/').slice(0, -1).join('/');
    }
    // 处理文件夹路径格式，确保没有开头的/
    const normalizedFolder = uploadFolder 
        ? uploadFolder.replace(/^\/+/, '') // 移除开头的/
            .replace(/\/{2,}/g, '/') // 替换多个连续的/为单个/
            .replace(/\/$/, '') // 移除末尾的/
        : '';

    const metadata = {
        FileName: fileName,
        FileType: fileType,
        FileSize: fileSize,
        UploadIP: uploadIp,
        UploadAddress: ipAddress,
        ListType: "None",
        TimeStamp: time,
        Label: "None",
        Folder: normalizedFolder || 'root',
    }


    let fileExt = fileName.split('.').pop(); // 文件扩展名
    if (!isExtValid(fileExt)) {
        // 如果文件名中没有扩展名，尝试从文件类型中获取
        fileExt = fileType.split('/').pop();
        if (fileExt === fileType || fileExt === '' || fileExt === null || fileExt === undefined) {
            // Type中无法获取扩展名
            fileExt = 'unknown' // 默认扩展名
        }
    }

    // 构建文件ID
    const nameType = url.searchParams.get('uploadNameType') || 'default'; // 获取命名方式
    const unique_index = time + Math.floor(Math.random() * 10000);
    let fullId = '';
    if (nameType === 'index') {
        // 只在 normalizedFolder 非空时添加路径
        fullId = normalizedFolder ? `${normalizedFolder}/${unique_index}.${fileExt}` : `${unique_index}.${fileExt}`;
    } else if (nameType === 'origin') {
        fullId = normalizedFolder ? `${normalizedFolder}/${fileName}` : fileName;
    } else if (nameType === 'short') {
        while (true) {
            const shortId = generateShortId(8);
            const testFullId = normalizedFolder ? `${normalizedFolder}/${shortId}.${fileExt}` : `${shortId}.${fileExt}`;
            if (await env.img_url.get(testFullId) === null) {
                fullId = testFullId;
                break;
            }
        }
    } else {
        fullId = normalizedFolder ? `${normalizedFolder}/${unique_index}_${fileName}` : `${unique_index}_${fileName}`;
    }

    // 获得返回链接格式, default为返回/file/id, full为返回完整链接
    const returnFormat = url.searchParams.get('returnFormat') || 'default';
    let returnLink = '';
    if (returnFormat === 'full') {
        returnLink = `${url.origin}/file/${fullId}`;
    } else {
        returnLink = `/file/${fullId}`;
    }

    // 清除CDN缓存
    const cdnUrl = `https://${url.hostname}/file/${fullId}`;
    await purgeCDNCache(env, cdnUrl, url, normalizedFolder);
   

    // ====================================不同渠道上传=======================================
    // 出错是否切换渠道自动重试，默认开启
    const autoRetry = url.searchParams.get('autoRetry') === 'false' ? false : true;

    let err = '';
    // 上传到不同渠道
    if (uploadChannel === 'CloudflareR2') {
        // -------------CloudFlare R2 渠道---------------
        const res = await uploadFileToCloudflareR2(env, fileToUpload, fullId, metadata, returnLink, url); // 使用 fileToUpload
        if (res.status === 200 || !autoRetry) {
            return res;
        } else {
            err = await res.text();
        }
    } else if (uploadChannel === 'S3') {
        // ---------------------S3 渠道------------------
        const res = await uploadFileToS3(env, fileToUpload, fullId, metadata, returnLink, url); // 使用 fileToUpload
        if (res.status === 200 || !autoRetry) {
            return res;
        } else {
            err = await res.text();
        }
    } else if (uploadChannel === 'External') {
        // --------------------外链渠道----------------------
        // 注意：External 渠道的逻辑已在文件获取部分处理，这里直接调用函数记录元数据
        // 它不涉及实际文件上传，所以不传递 fileToUpload
        const res = await uploadFileToExternal(env, formdata.get('url'), fullId, metadata, returnLink, url); // 传递提取的 URL
        return res; // External 渠道不参与重试
    } else {
        // ----------------Telegram New 渠道-------------------
        const res = await uploadFileToTelegram(env, fileToUpload, fullId, metadata, fileExt, fileName, fileType, url, clonedRequest, returnLink); // 使用 fileToUpload
        if (res.status === 200 || !autoRetry) {
            return res;
        } else {
            err = await res.text();
        }
    }

    // 上传失败，开始自动切换渠道重试 (External 渠道不参与)
    // 构造更详细的初始错误信息
    const initialErrorDetails = {
        channel: uploadChannel,
        message: err || 'Initial upload failed without specific error text.', // 使用 err 或默认消息
        status: res?.status, // 包含状态码（如果可用）
    };
    const retryResult = await tryRetry(initialErrorDetails, env, uploadChannel, fileToUpload, fullId, metadata, fileExt, fileName, fileType, url, clonedRequest, returnLink); // 传递详细错误对象, uploadChannel, 和 fileToUpload
    return retryResult;
}


// 自动切换渠道重试 (重构以改进错误处理和日志记录)
async function tryRetry(initialErrorDetails, env, initialUploadChannel, fileToUpload, fullId, metadata, fileExt, fileName, fileType, url, clonedRequest, returnLink) {
    const retryChannels = ['CloudflareR2', 'TelegramNew', 'S3']; // 渠道列表 (不包括 External)
    const allErrors = {}; // 用于收集所有尝试的错误

    // 记录初始错误 - 使用传入的 initialErrorDetails 对象
    allErrors[initialUploadChannel] = `Initial attempt failed: ${initialErrorDetails.message} (Status: ${initialErrorDetails.status || 'N/A'})`;

    for (const channel of retryChannels) {
        // 跳过初始失败的渠道和 External 渠道 (External 不参与重试)
        if (channel === initialUploadChannel || channel === 'External') {
            continue;
        }

        console.log(`Retrying upload with channel: ${channel}`); // 添加日志
        let retryResponse = null;
        let attemptError = null;

        try {
            if (channel === 'CloudflareR2') {
                retryResponse = await uploadFileToCloudflareR2(env, fileToUpload, fullId, metadata, returnLink, url);
            } else if (channel === 'TelegramNew') {
                retryResponse = await uploadFileToTelegram(env, fileToUpload, fullId, metadata, fileExt, fileName, fileType, url, clonedRequest, returnLink);
            } else if (channel === 'S3') {
                retryResponse = await uploadFileToS3(env, fileToUpload, fullId, metadata, returnLink, url);
            }

            // 检查重试是否成功
            if (retryResponse && retryResponse.status === 200) {
                console.log(`Retry successful with channel: ${channel}`); // 添加日志
                return retryResponse; // 成功，返回结果
            } else {
                // 重试失败，记录错误
                let errorText = `Retry failed with status ${retryResponse?.status || 'unknown'}`;
                if (retryResponse) {
                    try {
                        // 尝试读取响应体，但要处理可能的错误
                        const bodyText = await retryResponse.text();
                        errorText += `: ${bodyText}`;
                    } catch (e) {
                        errorText += ` (Failed to read response body: ${e.message})`;
                    }
                }
                attemptError = errorText;
            }
        } catch (retryError) {
             // 捕获重试过程中的代码执行异常
             console.error(`Exception during retry with ${channel}:`, retryError); // 添加详细错误日志
             attemptError = `Exception during retry: ${retryError.message}`;
        }

        // 记录本次尝试的错误
        if (attemptError) {
            allErrors[channel] = attemptError;
            console.warn(`Retry attempt failed for channel ${channel}: ${attemptError}`); // 添加警告日志
        }
    }

    // 所有重试均失败
    console.error("All upload attempts failed. Errors:", allErrors); // 记录最终错误摘要
    const finalErrorMessage = "All upload attempts failed. See Worker logs for details."; // 返回给客户端的通用错误
    // 返回包含详细错误信息的 JSON 对象
    return new Response(JSON.stringify({ error: finalErrorMessage, details: allErrors }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
    });
}

// 上传到Cloudflare R2
async function uploadFileToCloudflareR2(env, fileToUpload, fullId, metadata, returnLink, originUrl) { // 修改参数为 fileToUpload
    // 检查R2数据库是否配置
    if (!fileToUpload) return new Response('Error: No file content to upload to R2', { status: 400 }); // 添加检查
    if (typeof env.img_r2 == "undefined" || env.img_r2 == null || env.img_r2 == "") {
        return new Response('Error: Please configure R2 database', { status: 500 });
    }
    // 检查 R2 渠道是否启用
    const r2Settings = uploadConfig.cfr2;
    if (!r2Settings.channels || r2Settings.channels.length === 0) {
        return new Response('Error: No R2 channel provided', { status: 400 });
    }

    const r2Channel = r2Settings.channels[0];
    
    const R2DataBase = env.img_r2;

    // 写入R2数据库
    await R2DataBase.put(fullId, fileToUpload, { // 使用 fileToUpload
        httpMetadata: { contentType: fileToUpload.type }, // 显式设置 ContentType
    });

    // 更新metadata
    metadata.Channel = "CloudflareR2";
    metadata.ChannelName = "R2_env";

    // 图像审查，采用R2的publicUrl
    const R2PublicUrl = r2Channel.publicUrl;
    let moderateUrl = `${R2PublicUrl}/${fullId}`;
    metadata = await moderateContent(env, moderateUrl, metadata);

    // 写入KV数据库
    try {
        await env.img_url.put(fullId, "", {
            metadata: metadata,
        });
    } catch (error) {
        return new Response('Error: Failed to write to KV database', { status: 500 });
    }


    // 成功上传，将文件ID返回给客户端
    return new Response(
        JSON.stringify([{ 'src': `${returnLink}` }]), 
        {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        }
    );
}



// 上传到 S3（支持自定义端点）
async function uploadFileToS3(env, fileToUpload, fullId, metadata, returnLink, originUrl) { // 修改参数为 fileToUpload
    if (!fileToUpload) return new Response('Error: No file content to upload to S3', { status: 400 }); // 添加检查
    const s3Settings = uploadConfig.s3;
    const s3Channels = s3Settings.channels;
    const s3Channel = s3Settings.loadBalance.enabled
        ? s3Channels[Math.floor(Math.random() * s3Channels.length)]
        : s3Channels[0];

    if (!s3Channel) {
        return new Response('Error: No S3 channel provided', { status: 400 });
    }

    const { endpoint, accessKeyId, secretAccessKey, bucketName, region } = s3Channel;

    // 创建 S3 客户端
    const s3Client = new S3Client({
        region: region || "auto", // R2 可用 "auto"
        endpoint, // 自定义 S3 端点
        credentials: {
            accessKeyId,
            secretAccessKey
        }
    });

    // 获取文件内容 (已经是 Blob 或 File)
    if (!fileToUpload) return new Response("Error: No file provided", { status: 400 }); // 重复检查以防万一

    // 转换 Blob/File 为 ArrayBuffer (S3 SDK 需要)
    const arrayBuffer = await fileToUpload.arrayBuffer();
    // const uint8Array = new Uint8Array(arrayBuffer); // SDK v3 putObjectCommand可以直接接受ArrayBuffer

    const s3FileName = fullId;

    try {
        // S3 上传参数
        const putObjectParams = {
            Bucket: bucketName,
            Key: s3FileName,
            Body: arrayBuffer, // 使用 ArrayBuffer
            ContentType: fileToUpload.type // 使用传入对象的类型
        };

        // 执行上传
        await s3Client.send(new PutObjectCommand(putObjectParams));

        // 更新 metadata
        metadata.Channel = "S3";
        metadata.ChannelName = s3Channel.name;

        const s3ServerDomain = endpoint.replace(/https?:\/\//, "");
        metadata.S3Location = `https://${bucketName}.${s3ServerDomain}/${s3FileName}`; // 采用虚拟主机风格的 URL
        metadata.S3Endpoint = endpoint;
        metadata.S3AccessKeyId = accessKeyId;
        metadata.S3SecretAccessKey = secretAccessKey;
        metadata.S3Region = region || "auto";
        metadata.S3BucketName = bucketName;
        metadata.S3FileKey = s3FileName;

        // 图像审查
        if (moderateContentApiKey) {
            try {
                await env.img_url.put(fullId, "", { metadata });
            } catch {
                return new Response("Error: Failed to write to KV database", { status: 500 });
            }

            const moderateUrl = `https://${originUrl.hostname}/file/${fullId}`;
            metadata = await moderateContent(env, moderateUrl, metadata);
            await purgeCDNCache(env, moderateUrl, originUrl);
        }

        // 写入 KV 数据库
        try {
            await env.img_url.put(fullId, "", { metadata });
        } catch {
            return new Response("Error: Failed to write to KV database", { status: 500 });
        }

        return new Response(JSON.stringify([{ src: returnLink }]), {
            status: 200,
            headers: { "Content-Type": "application/json" },
        });
    } catch (error) {
        return new Response(`Error: Failed to upload to S3 - ${error.message}`, { status: 500 });
    }
}

// 上传到Telegram
async function uploadFileToTelegram(env, fileToUpload, fullId, metadata, fileExt, fileName, fileType, url, clonedRequest, returnLink) { // 修改参数为 fileToUpload
    if (!fileToUpload) return new Response('Error: No file content to upload to Telegram', { status: 400 }); // 添加检查
    // 选择一个 Telegram 渠道上传，若负载均衡开启，则随机选择一个；否则选择第一个
    const tgSettings = uploadConfig.telegram;
    const tgChannels = tgSettings.channels;
    const tgChannel = tgSettings.loadBalance.enabled? tgChannels[Math.floor(Math.random() * tgChannels.length)] : tgChannels[0];
    if (!tgChannel) {
        return new Response('Error: No Telegram channel provided', { status: 400 });
    }

    const tgBotToken = tgChannel.botToken;
    const tgChatId = tgChannel.chatId;

    let fileToSend = fileToUpload; // 默认使用传入的文件

    // 由于TG会把gif/webp后缀的文件转为视频，所以需要修改后缀名绕过限制
    // 注意：这里创建了新的 File 对象，需要确保后续使用这个 newFile
    if (fileExt === 'gif') {
        const newFileName = fileName.replace(/\.gif$/, '.jpeg');
        // 从原始 fileToUpload 创建新 File，而不是 formdata.get('file')
        fileToSend = new File([await fileToUpload.arrayBuffer()], newFileName, { type: 'image/jpeg' }); // 使用修改后的类型
    } else if (fileExt === 'webp') {
        const newFileName = fileName.replace(/\.webp$/, '.jpeg');
        fileToSend = new File([await fileToUpload.arrayBuffer()], newFileName, { type: 'image/jpeg' }); // 使用修改后的类型
    }

    // 选择对应的发送接口
    const fileTypeMap = {
        'image/': {'url': 'sendPhoto', 'type': 'photo'},
        'video/': {'url': 'sendVideo', 'type': 'video'},
        'audio/': {'url': 'sendAudio', 'type': 'audio'},
        'application/pdf': {'url': 'sendDocument', 'type': 'document'},
    };

    const defaultType = {'url': 'sendDocument', 'type': 'document'};

    let sendFunction = Object.keys(fileTypeMap).find(key => fileType.startsWith(key)) 
        ? fileTypeMap[Object.keys(fileTypeMap).find(key => fileType.startsWith(key))] 
        : defaultType;

    // GIF 发送接口特殊处理
    if (fileType === 'image/gif' || fileType === 'image/webp' || fileExt === 'gif' || fileExt === 'webp') {
        sendFunction = {'url': 'sendAnimation', 'type': 'animation'};
    }

    // 根据服务端压缩设置处理接口：从参数中获取serverCompress，如果为false，则使用sendDocument接口
    if (url.searchParams.get('serverCompress') === 'false') {
        sendFunction = {'url': 'sendDocument', 'type': 'document'};
    }

    // 根据发送接口向表单嵌入chat_id
    let newFormdata = new FormData();
    newFormdata.append('chat_id', tgChatId);
    newFormdata.append(sendFunction.type, fileToSend, fileToSend.name); // 使用处理后的 fileToSend，并传递文件名

    // 构建目标 URL 
    // const targetUrl = new URL(url.pathname, 'https://telegra.ph'); // telegraph接口，已失效，缅怀
    const targetUrl = new URL(`https://api.telegram.org/bot${tgBotToken}/${sendFunction.url}`); // telegram接口
    // 目标 URL 剔除 authCode 参数
    url.searchParams.forEach((value, key) => {
        if (key !== 'authCode') {
            targetUrl.searchParams.append(key, value);
        }
    });
    // 复制请求头并剔除 authCode
    const headers = new Headers(clonedRequest.headers);
    headers.delete('authCode');


    // 向目标 URL 发送请求
    let res = new Response('upload error, check your environment params about telegram channel!', { status: 400 });
    try {
        const response = await fetch(targetUrl.href, {
            method: clonedRequest.method,
            headers: {
                "User-Agent": " Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
            },
            body: newFormdata,
        });
        const clonedRes = await response.clone().json(); // 等待响应克隆和解析完成
        const fileInfo = getFile(clonedRes);
        const filePath = await getFilePath(tgBotToken, fileInfo.file_id);
        const id = fileInfo.file_id;
        // 更新FileSize
        metadata.FileSize = (fileInfo.file_size / 1024 / 1024).toFixed(2);

        // 若上传成功，将响应返回给客户端
        if (response.ok) {
            res = new Response(
                JSON.stringify([{ 'src': `${returnLink}` }]),
                {
                    status: 200,
                    headers: { 'Content-Type': 'application/json' }
                }
            );
        }


        // 图像审查
        const moderateUrl = `https://api.telegram.org/file/bot${tgBotToken}/${filePath}`;
        metadata = await moderateContent(env, moderateUrl, metadata);

        // 更新metadata，写入KV数据库
        try {
            metadata.Channel = "TelegramNew";
            metadata.ChannelName = tgChannel.name;

            metadata.TgFileId = id;
            metadata.TgChatId = tgChatId;
            metadata.TgBotToken = tgBotToken;
            await env.img_url.put(fullId, "", {
                metadata: metadata,
            });
        } catch (error) {
            res = new Response('Error: Failed to write to KV database', { status: 500 });
        }
    } catch (error) {
        res = new Response('upload error, check your environment params about telegram channel!', { status: 400 });
    } finally {
        return res;
    }
}


// 外链渠道
async function uploadFileToExternal(env, extUrl, fullId, metadata, returnLink, originUrl) { // 接收 extUrl 而不是 formdata
    // 直接将外链写入metadata
    metadata.Channel = "External";
    metadata.ChannelName = "External";
    // 外链已作为参数传入
    if (extUrl === null || extUrl === undefined || extUrl.trim() === '') {
        return new Response('Error: No url provided for external channel', { status: 400 });
    }
    metadata.ExternalLink = extUrl;
    // 写入KV数据库
    try {
        await env.img_url.put(fullId, "", {
            metadata: metadata,
        });
    } catch (error) {
        return new Response('Error: Failed to write to KV database', { status: 500 });
    }

    // 返回结果
    return new Response(
        JSON.stringify([{ 'src': `${returnLink}` }]), 
        {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        }
    );
}


// 图像审查
async function moderateContent(env, url, metadata) {
    const apikey = moderateContentApiKey;
    if (apikey == undefined || apikey == null || apikey == "") {
        metadata.Label = "None";
    } else {
        try {
            const fetchResponse = await fetch(`https://api.moderatecontent.com/moderate/?key=${apikey}&url=${url}`);
            if (!fetchResponse.ok) {
                throw new Error(`HTTP error! status: ${fetchResponse.status}`);
            }
            const moderate_data = await fetchResponse.json();
            if (moderate_data.rating_label) {
                metadata.Label = moderate_data.rating_label;
            }
        } catch (error) {
            console.error('Moderate Error:', error);
            // 将不带审查的图片写入数据库
            metadata.Label = "None";
        } finally {
            console.log('Moderate Done');
        }
    }
    return metadata;
}

function getFile(response) {
    try {
		if (!response.ok) {
			return null;
		}

		const getFileDetails = (file) => ({
			file_id: file.file_id,
			file_name: file.file_name || file.file_unique_id,
            file_size: file.file_size,
		});

		if (response.result.photo) {
			const largestPhoto = response.result.photo.reduce((prev, current) =>
				(prev.file_size > current.file_size) ? prev : current
			);
			return getFileDetails(largestPhoto);
		}

		if (response.result.video) {
			return getFileDetails(response.result.video);
		}

        if (response.result.audio) {
            return getFileDetails(response.result.audio);
        }

		if (response.result.document) {
			return getFileDetails(response.result.document);
		}

		return null;
	} catch (error) {
		console.error('Error getting file id:', error.message);
		return null;
	}
}

async function getFilePath(bot_token, file_id) {
    try {
        const url = `https://api.telegram.org/bot${bot_token}/getFile?file_id=${file_id}`;
        const res = await fetch(url, {
          method: 'GET',
          headers: {
            "User-Agent": " Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome"
          },
        })
    
        let responseData = await res.json();
        if (responseData.ok) {
          const file_path = responseData.result.file_path
          return file_path
        } else {
          return null;
        }
      } catch (error) {
        return null;
      }
}

async function purgeCDNCache(env, cdnUrl, url, normalizedFolder) {
    if (env.dev_mode === 'true') {
        return;
    }

    // 清除CDN缓存
    try {
        await purgeCFCache(env, cdnUrl);
    } catch (error) {
        console.error('Failed to clear CDN cache:', error);
    }

    // 清除api/randomFileList API缓存
    try {
        const cache = caches.default;
        // await cache.delete(`${url.origin}/api/randomFileList`); delete有bug，通过写入一个max-age=0的response来清除缓存
        const nullResponse = new Response(null, {
            headers: { 'Cache-Control': 'max-age=0' },
        });

        await cache.put(`${url.origin}/api/randomFileList?dir=${normalizedFolder}`, nullResponse);
    } catch (error) {
        console.error('Failed to clear cache:', error);
    }
}

function isExtValid(fileExt) {
    return ['jpeg', 'jpg', 'png', 'gif', 'webp', 
    'mp4', 'mp3', 'ogg',
    'mp3', 'wav', 'flac', 'aac', 'opus',
    'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'pdf', 
    'txt', 'md', 'json', 'xml', 'html', 'css', 'js', 'ts', 'go', 'java', 'php', 'py', 'rb', 'sh', 'bat', 'cmd', 'ps1', 'psm1', 'psd', 'ai', 'sketch', 'fig', 'svg', 'eps', 'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'apk', 'exe', 'msi', 'dmg', 'iso', 'torrent', 'webp', 'ico', 'svg', 'ttf', 'otf', 'woff', 'woff2', 'eot', 'apk', 'crx', 'xpi', 'deb', 'rpm', 'jar', 'war', 'ear', 'img', 'iso', 'vdi', 'ova', 'ovf', 'qcow2', 'vmdk', 'vhd', 'vhdx', 'pvm', 'dsk', 'hdd', 'bin', 'cue', 'mds', 'mdf', 'nrg', 'ccd', 'cif', 'c2d', 'daa', 'b6t', 'b5t', 'bwt', 'isz', 'isz', 'cdi', 'flp', 'uif', 'xdi', 'sdi'
    ].includes(fileExt);
}

async function isBlockedUploadIp(env, uploadIp) {
    // 检查是否配置了KV数据库
    if (typeof env.img_url == "undefined" || env.img_url == null || env.img_url == "") {
        return false;
    }

    const kv = env.img_url;
    let list = await kv.get("manage@blockipList");
    if (list == null) {
        list = [];
    } else {
        list = list.split(",");
    }

    return list.includes(uploadIp);
}

// 生成短链接
function generateShortId(length = 8) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}


// 获取IP地址
async function getIPAddress(ip) {
    let address = '未知';
    try {
        const ipInfo = await fetch(`https://apimobile.meituan.com/locate/v2/ip/loc?rgeo=true&ip=${ip}`);
        const ipData = await ipInfo.json();
        
        if (ipInfo.ok && ipData.data) {
            const lng = ipData.data?.lng || 0;
            const lat = ipData.data?.lat || 0;
            
            // 读取具体地址
            const addressInfo = await fetch(`https://apimobile.meituan.com/group/v1/city/latlng/${lat},${lng}?tag=0`);
            const addressData = await addressInfo.json();

            if (addressInfo.ok && addressData.data) {
                // 根据各字段是否存在，拼接地址
                address = [
                    addressData.data.detail,
                    addressData.data.city,
                    addressData.data.province,
                    addressData.data.country
                ].filter(Boolean).join(', ');
            }
        }
    } catch (error) {
        console.error('Error fetching IP address:', error);
    }
    return address;
}
