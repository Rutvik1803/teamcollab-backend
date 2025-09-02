import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

function fromRefreshCookie(req: Request) {
    const token = req.cookies?.rt; // httpOnly cookie set by our server
    if (!token) return null;
    return token;
}

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
    constructor(config: ConfigService) {
        super({
            jwtFromRequest: ExtractJwt.fromExtractors([
                fromRefreshCookie,
                ExtractJwt.fromBodyField('refreshToken'), // fallback for tests
            ]),
            secretOrKey: config.get<string>('JWT_REFRESH_SECRET'),
            passReqToCallback: true,
        });
    }

    async validate(req: Request, payload: { sub: string; email: string }) {
        const token =
            req.cookies?.rt || (req.body && (req.body as any).refreshToken);
        if (!token) throw new UnauthorizedException('No refresh token');
        // We only attach payload; AuthService will compare hashedRt in DB
        return { ...payload, refreshToken: token };
    }
}
