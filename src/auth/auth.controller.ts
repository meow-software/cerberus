import { BadRequestException, Body, Controller, Get, Headers, HttpCode, HttpStatus, Inject, Post, Query, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshDto } from './dto/refresh.dto';
import Request from 'express';
import { ClientCredentialsDto } from './dto/client-credentials.dto';
import { ResendConfirmationDto } from './dto/resend-confirmation.dto';
import { ResetPasswordDemandDto } from './dto/reset-password.dto';
import { ResetPasswordConfirmationDto } from './dto/reset-password-confirmation.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) { }

  @Post('register')
  async register(@Body() dto: RegisterDto) {
    return this.auth.register(dto.email, dto.password, dto.role);
  }

  @Get('register/confirm')
  async registerConfirm(@Query('token') token: string) {
    if (!token) throw new BadRequestException('Token required');
    return this.auth.confirmRegister(token);
  }

  @Post('register/confirm/resend')
  async resendConfirmation(@Body('email') dto: ResendConfirmationDto,
    @Req() req: Request
  ) {
    return this.auth.resendConfirmationEmail(dto.id, req.headers);
  }

  @Post('login')
  async login(@Body() dto: LoginDto) {
    return this.auth.login(dto.email, dto.password);
  }

  @Post('bot/login')
  async getBotToken(@Body() dto: ClientCredentialsDto) {
    return this.auth.getBotToken(dto.id, dto.clientSecret);
  }

  @Post('refresh')
  async refresh(
    @Body('refreshToken') dto: RefreshDto,
    @Headers('authorization') authorization?: string) {
    const accessToken = authorization?.replace('Bearer ', '');
    return this.auth.refresh(dto.refreshToken, accessToken);
  }

  @Post('reset-password/demand')
  async resetPasswordDemand(
    @Body() dto: ResetPasswordDemandDto,
    @Req() req: Request) {
    return this.auth.resetPasswordDemand(dto.id, req.headers);
  }


  @Post('reset-password/confirmation')
  async resetPasswordConfirmation(
    @Body() dto: ResetPasswordConfirmationDto,
    @Req() req: Request
  ) {
    return this.auth.resetPasswordConfirmation(dto.code, dto.id, dto.password, dto.oldPassword, req.headers);
  }

  @Post('logout')
  async logout(@Body() dto: RefreshDto, @Req() req: Request) {
    const accessJti = req.headers['x-access-jti'] as string | undefined;
    return this.auth.logout(dto.refreshToken, accessJti);
  }
}
