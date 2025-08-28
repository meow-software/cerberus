import { IsNotEmpty, IsString, Length, MinLength } from 'class-validator';
import { SnowflakeDto } from './abstract/snowflake-abstract.dto';

export class ResetPasswordConfirmationDto extends SnowflakeDto {
    @IsString()
    @Length(6)
    code: string

    @IsString()
    @IsNotEmpty()
    @MinLength(8)
    password : string
    
    @IsString()
    @IsNotEmpty()
    @MinLength(8)
    oldPassword : string
}
