import { Body, Controller, HttpCode, HttpStatus, Inject, Post, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshDto } from './dto/refresh.dto';
import Request from 'express';
import { ClientCredentialsDto } from './dto/bot-credentials.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) { }

  @Post('register')
  async register(@Body() dto: RegisterDto) {
    console.log("--la")
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
    const accessJti = req.headers['x-access-jti'] as string | undefined;
    return this.auth.logout(dto.refreshToken, accessJti);
  }
  @Post('bot/login')
  async getBotToken(@Body() dto: ClientCredentialsDto) {
    return this.auth.getBotToken(dto.clientId, dto.clientSecret);
  }
}
