import { Body, Controller, HttpCode, HttpStatus, Inject, Post, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshDto } from './dto/refresh.dto';
import Request  from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post('register')
  async register(@Body() dto: RegisterDto) {
    // On délègue la création à USER_SERVICE côté service
    return this.auth.register(dto.email, dto.password, dto.role);
  }

  @Post('login')
  async login(@Body() dto: LoginDto) {
    return this.auth.login(dto.email, dto.password);
  }
  
  @Post('refresh')
  async refresh(@Body() dto: RefreshDto) {
    return this.auth.refresh(dto.refreshToken, dto.accessToken);
  }
  
  @Post('logout')
  async logout(@Body() dto: RefreshDto, @Req() req: Request) {
    // Si tu passes l'access token en Authorization: Bearer xxx, récupère son jti si présent dans req.user
    // Ici on n’est pas derrière JwtGuard sur /logout, donc pas de req.user; on peut le passer en header custom
    const accessJti = req.headers['x-access-jti'] as string | undefined;
    return this.auth.logout(dto.refreshToken, accessJti);
  }
}
