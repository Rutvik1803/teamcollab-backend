import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/roles.guard';
import { Roles } from 'src/auth/roles.decorator';

@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard)
export class UsersController {
    constructor(private readonly usersService: UsersService) { }

    @Get('admin-stats')
    @Roles('Admin') // role must match user.role string
    getAdminStats() {
        return { totalUsers: 42 }; // demo
    }

    @Get()
    getAllUsers() {
        return this.usersService.findAll();
    }

    @Post()
    createUser(@Body() body: { name: string, email: string, password: string, role: string }) {
        return this.usersService.createUser(body);
    }
}
