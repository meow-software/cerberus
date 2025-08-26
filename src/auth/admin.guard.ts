import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';

@Injectable()
export class AdminGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    console.log("--Admin guard active depusi cerberus")
    const req = ctx.switchToHttp().getRequest();
    return req.user?.role === 'admin';
  }
}
