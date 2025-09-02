import { ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService,
    ) { }

    private async hash(data: string) {
        const salt = await bcrypt.genSalt(10);
        return bcrypt.hash(data, salt);
    }

    private async verify(plain: string, hash: string) {
        return bcrypt.compare(plain, hash);
    }

    private async getTokens(userId: string, email: string, role: string, name: string) {
        const payload = { sub: userId, email, role, name };
        const at = await this.jwt.signAsync(payload, {
            secret: this.config.get('JWT_ACCESS_SECRET'),
            expiresIn: this.config.get('ACCESS_TOKEN_TTL') || '15m',
        });
        const rt = await this.jwt.signAsync({ sub: userId, email }, {
            secret: this.config.get('JWT_REFRESH_SECRET'),
            expiresIn: this.config.get('REFRESH_TOKEN_TTL') || '7d',
        });
        return { accessToken: at, refreshToken: rt };
    }

    async register(dto: { name: string; email: string; password: string; role?: string }) {
        const exists = await this.prisma.user.findUnique({ where: { email: dto.email } });
        if (exists) throw new ForbiddenException('Email already in use');

        const passwordHash = await this.hash(dto.password);
        const user = await this.prisma.user.create({
            data: {
                name: dto.name,
                email: dto.email,
                password: passwordHash,
                role: dto.role ?? 'Employee',
            },
        });

        const tokens = await this.getTokens(user.id, user.email, user.role, user.name);
        const hashedRt = await this.hash(tokens.refreshToken);
        await this.prisma.user.update({
            where: { id: user.id },
            data: { hashedRt },
        });

        return { user: { id: user.id, name: user.name, email: user.email, role: user.role }, ...tokens };
    }

    async login(dto: { email: string; password: string }) {
        const user = await this.prisma.user.findUnique({ where: { email: dto.email } });
        if (!user) throw new UnauthorizedException('Invalid credentials');

        const match = await this.verify(dto.password, user.password);
        if (!match) throw new UnauthorizedException('Invalid credentials');

        const tokens = await this.getTokens(user.id, user.email, user.role, user.name);
        const hashedRt = await this.hash(tokens.refreshToken);
        await this.prisma.user.update({ where: { id: user.id }, data: { hashedRt } });

        return { user: { id: user.id, name: user.name, email: user.email, role: user.role }, ...tokens };
    }

    async logout(userId: string) {
        await this.prisma.user.update({
            where: { id: userId },
            data: { hashedRt: null },
        });
        return { success: true };
    }

    async refresh(userId: string, refreshToken: string) {
        const user = await this.prisma.user.findUnique({ where: { id: userId } });
        if (!user || !user.hashedRt) throw new UnauthorizedException('No session');

        const valid = await bcrypt.compare(refreshToken, user.hashedRt);
        if (!valid) throw new UnauthorizedException('Invalid refresh token');

        // ROTATE tokens
        const tokens = await this.getTokens(user.id, user.email, user.role, user.name);
        const hashedRt = await this.hash(tokens.refreshToken);
        await this.prisma.user.update({ where: { id: user.id }, data: { hashedRt } });

        return { user: { id: user.id, name: user.name, email: user.email, role: user.role }, ...tokens };
    }
}
