import { Body, Controller, Get, Post } from '@nestjs/common';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
    constructor(private readonly usersService: UsersService) { }

    @Get()
    getAllUsers() {
        return this.usersService.findAll();
    }

    @Post()
    createUser(@Body() body: { name: string, email: string, password: string, role: string }) {
        return this.usersService.createUser(body);
    }
}
