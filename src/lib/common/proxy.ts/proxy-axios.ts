import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';
import { HttpProxy } from './http-proxy.interface';

export class AxiosProxy implements HttpProxy {
    protected readonly client: AxiosInstance;
    protected baseURL: string;

    constructor(baseURL: string) {
        this.client = axios.create({
            timeout: 5000,
        });
        this.baseURL = baseURL;
    }

    getBaseUrl(): string {
        return this.baseURL;
    }

    async get<T>(target: string, config?: AxiosRequestConfig): Promise<T> {
        const { data } = await this.client.get<T>(this.getBaseUrl() + target, config);
        return data;
    }

    async post<T>(target: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
        const { data: res } = await this.client.post<T>(this.getBaseUrl() + target, data, config);
        return res;
    }

    async put<T>(target: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
        const { data: res } = await this.client.put<T>(this.getBaseUrl() + target, data, config);
        return res;
    }

    async patch<T>(target: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
        const { data: res } = await this.client.patch<T>(this.baseURL + target, data, config);
        return res;
    }

    async delete<T>(target: string, config?: AxiosRequestConfig): Promise<T> {
        const { data } = await this.client.delete<T>(this.getBaseUrl() + target, config);
        return data;
    }
}
