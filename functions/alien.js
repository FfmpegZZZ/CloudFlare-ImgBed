import { onRequestPost as originalOnRequestPost } from './upload.js';

export async function onRequestPost(context) {
    const { request, env, params, waitUntil, next, data } = context;

    // 克隆原始请求URL
    const originalUrl = new URL(request.url);

    // 创建一个新的URL对象用于修改
    const modifiedUrl = new URL(originalUrl);

    // 设置默认参数
    modifiedUrl.searchParams.set('uploadChannel', 'cfr2');
    modifiedUrl.searchParams.set('serverCompress', 'false');
    modifiedUrl.searchParams.set('uploadNameType', 'origin');
    modifiedUrl.searchParams.set('uploadFolder', '/Alien');
    modifiedUrl.searchParams.set('returnFormat', 'full');
    modifiedUrl.searchParams.set('authCode', '114514');
    modifiedUrl.searchParams.set('action', 'fetch');

    // 创建一个新的Request对象，使用修改后的URL
    // 注意：需要克隆原始请求以保留方法、头部和主体
    const modifiedRequest = new Request(modifiedUrl.toString(), {
        method: request.method,
        headers: request.headers,
        body: request.body,
        redirect: request.redirect // 保留其他可能的请求属性
    });

    // 创建一个新的上下文对象，包含修改后的请求和URL
    const modifiedContext = {
        request: modifiedRequest,
        env,
        params,
        waitUntil,
        next,
        data,
        // 如果原始上下文还有其他属性，也应传递
    };

    // 调用原始的onRequestPost处理函数
    return originalOnRequestPost(modifiedContext);
}
