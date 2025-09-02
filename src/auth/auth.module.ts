import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { ConfigModule } from '@nestjs/config';
import { DatabaseModule } from 'src/database/database.module';
import { UsersModule } from 'src/users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { JwtAccessStrategy } from './strategies/jwt-access.strategy';

@Module({
  imports: [
    ConfigModule,
    DatabaseModule,
    UsersModule,
    JwtModule.register({})
  ],
  providers: [AuthService, JwtAccessStrategy],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule { }
