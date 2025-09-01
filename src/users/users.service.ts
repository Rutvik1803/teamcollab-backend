import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';

@Injectable()
export class UsersService {
    constructor(private readonly prisma: PrismaService) { }
    // Define methods for user-related operations here
    async findAll() {
        // Logic to retrieve all users
        return this.prisma.user.findMany();
    }

    async createUser(data: { name: string, email: string, password: string, role: string }) {
        // Logic to create a new user
        return this.prisma.user.create({ data });
    }

}
