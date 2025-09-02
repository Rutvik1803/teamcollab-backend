import { Body, Controller, Get, HttpCode, Post, Req, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Response, Request } from 'express';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';

// Extend the Express Request interface
declare global {
    namespace Express {
        interface Request {
            user?: any;
        }
    }
}

const cookieOpts = {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: process.env.NODE_ENV === 'production',
    path: '/',
};

@Controller('auth')
export class AuthController {
    constructor(private auth: AuthService) { }

    @Post('register')
    async register(
        @Body() dto: { name: string; email: string; password: string; role?: string },
        @Res({ passthrough: true }) res: Response,
    ) {
        const result = await this.auth.register(dto);
        res.cookie('rt', result.refreshToken, { ...cookieOpts, maxAge: 7 * 24 * 3600 * 1000 });
        return { user: result.user, accessToken: result.accessToken };
    }

    @HttpCode(200)
    @Post('login')
    async login(
        @Body() dto: { email: string; password: string },
        @Res({ passthrough: true }) res: Response,
    ) {
        const result = await this.auth.login(dto);
        res.cookie('rt', result.refreshToken, { ...cookieOpts, maxAge: 7 * 24 * 3600 * 1000 });
        return { user: result.user, accessToken: result.accessToken };
    }

    @UseGuards(JwtRefreshGuard)
    @Post('refresh')
    async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
        const payload = req.user as { sub: string; email: string; refreshToken: string };
        const result = await this.auth.refresh(payload.sub, payload.refreshToken);
        res.cookie('rt', result.refreshToken, { ...cookieOpts, maxAge: 7 * 24 * 3600 * 1000 });
        return { user: result.user, accessToken: result.accessToken };
    }

    @UseGuards(JwtAuthGuard)
    @Post('logout')
    async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
        const user = req.user as { sub: string };
        await this.auth.logout(user.sub);
        res.clearCookie('rt', { ...cookieOpts });
        return { success: true };
    }

    @UseGuards(JwtAuthGuard)
    @Get('me')
    me(@Req() req: Request) {
        return req.user; // { sub, email, role, name }
    }
}
