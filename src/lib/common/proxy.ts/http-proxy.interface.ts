export interface HttpProxy {
    getBaseUrl(): string;
    get<T = any>(target: string, config?: any): Promise<T>;
    post<T = any>(target: string, data?: any, config?: any): Promise<T>;
    put<T = any>(target: string, data?: any, config?: any): Promise<T>;
    patch<T = any>(target: string, data?: any, config?: any): Promise<T>;
    delete<T = any>(target: string, config?: any): Promise<T>;
}