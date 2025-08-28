import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from './jwt.strategy';
import { JwtAuthGuard } from './jwt-auth-guard';
import { AdminGuard } from './admin.guard';
import { RedisModule } from '../redis/redis.module';
import { UserProxyService } from './proxy/user-proxy.service';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    // JwtModule est utilisé ici pour signer/verify (service)
    JwtModule.register({}), // clés passées à chaque sign/verify dynamiquement
    RedisModule,
    // ClientsModule.register([
    //   {
    //     name: "USER_SERVICE",
    //     transport: Transport.TCP,
    //     options: {
    //       host: process.env.USER_SERVICE_HOST || '127.0.0.1',
    //       port: parseInt(process.env.USER_SERVICE_PORT || '4010', 10),
    //     },
    //   },
    // ]),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, JwtAuthGuard, AdminGuard, UserProxyService],
  exports: [JwtAuthGuard, AdminGuard],
})
export class AuthModule { }
