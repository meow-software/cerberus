import { IsString, Length } from 'class-validator';

export abstract class SnowflakeDto {
    @Length(18)
    @IsString() 
    id : string
}
